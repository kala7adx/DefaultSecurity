"""Worker behaviour added after the Phase 0 connectors/worker security review
(docs/reviews/phase-0-connectors-worker-review.md). Each test names the finding it covers."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, insert, select, update
from worker_helpers import add_fake_integration

from skyline_checks.loader import LoadedCheck
from skyline_connectors.base import ApiCall, Scope, TransientError
from skyline_connectors.fake.connector import FakeConnector
from skyline_connectors.runner import RunnerLimits, ScopeResult
from skyline_core.db.models import (
    Asset,
    AuditLog,
    Finding,
    FindingEvent,
    Integration,
    Job,
    JobKind,
    ScanRun,
)
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.queue import ClaimedJob, EvaluatePayload, ScanPayload
from skyline_worker.catalogue import catalogue_drift
from skyline_worker.context import WorkerContext
from skyline_worker.pipeline.scan import READ_ONLY_REASON, LeaseLostError, run_scan
from skyline_worker.pipeline.store import store_results
from skyline_worker.pipeline.verify import GAVE_UP_DETAIL
from skyline_worker.runner import Worker
from testsupport import Database, TenantFixture

pytestmark = pytest.mark.db

ALL_FIXES = ["remove_public_ip", "close_admin_ports", "encrypt_bucket", "enable_mfa", "upgrade_os"]


class _RollbackError(Exception):
    """Raised to roll back a test transaction after inspecting it."""


async def _drain(worker: Worker) -> int:
    ran = 0
    while await worker.run_once():
        ran += 1
    return ran


async def _onboard(db: Database, tenant: TenantFixture, worker: Worker) -> UUID:
    integration_id = await add_fake_integration(db, tenant)
    assert await _drain(worker) == 2
    return integration_id


async def _new_run(
    db: Database, tenant: TenantFixture, integration_id: UUID, worker: Worker, *, enqueue: bool
) -> UUID:
    scan_run_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(ScanRun).values(
                id=scan_run_id, tenant_id=tenant.id, integration_id=integration_id, trigger="manual"
            )
        )
        if enqueue:
            await worker.ctx.queue.enqueue(
                session,
                tenant_id=tenant.id,
                payload=ScanPayload(scan_run_id=scan_run_id, integration_id=integration_id),
            )
    return scan_run_id


async def _reconfigure(
    db: Database,
    tenant: TenantFixture,
    integration_id: UUID,
    config: dict[str, Any],
    worker: Worker,
) -> ScanRun:
    from skyline_core.queue import VerifyIntegrationPayload

    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            update(Integration).where(Integration.id == integration_id).values(config=config)
        )
        await worker.ctx.queue.enqueue(
            session,
            tenant_id=tenant.id,
            payload=VerifyIntegrationPayload(integration_id=integration_id),
        )
    await _drain(worker)
    return await _latest_run(db, tenant)


async def _latest_run(db: Database, tenant: TenantFixture) -> ScanRun:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return (
            await session.execute(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(1))
        ).scalar_one()


async def _run(db: Database, tenant: TenantFixture, scan_run_id: UUID) -> ScanRun:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return (
            await session.execute(select(ScanRun).where(ScanRun.id == scan_run_id))
        ).scalar_one()


async def _integration(db: Database, tenant: TenantFixture, integration_id: UUID) -> Integration:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return (
            await session.execute(select(Integration).where(Integration.id == integration_id))
        ).scalar_one()


async def _finding_statuses(db: Database, tenant: TenantFixture) -> list[str]:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return list((await session.execute(select(Finding.status))).scalars())


async def _scan_runs(db: Database, tenant: TenantFixture) -> int:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return (await session.execute(select(func.count()).select_from(ScanRun))).scalar_one()


# ------------------------------------------------------------------ H1: rejected != deleted


async def test_rejected_records_keep_their_assets_and_open_findings(
    db: Database, ready_tenant: TenantFixture, worker: Worker, ctx: WorkerContext
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    # Every record is "too large" now, while the fixes would otherwise resolve everything.
    strict = Worker(replace(ctx, runner_limits=RunnerLimits(max_raw_config_bytes=8)))
    scan = await _reconfigure(db, tenant, integration_id, {"simulate_fixes": ALL_FIXES}, strict)
    assert scan.status == "succeeded"
    assert scan.stats["records_rejected"] >= 12
    assert scan.stats["assets_deleted"] == 0
    assert scan.stats["resolved"] == 0 and scan.stats["skipped_stale"] > 0
    assert set(await _finding_statuses(db, tenant)) == {"open"}
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        deleted = (
            await session.execute(
                select(func.count()).select_from(Asset).where(Asset.deleted_at.is_not(None))
            )
        ).scalar()
    assert deleted == 0


async def test_scope_with_an_unusable_record_id_deletes_nothing(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    run_id = await _new_run(db, tenant, integration_id, worker, enqueue=False)
    north = Scope(kind="region", id="fake-north-1")

    async def store(result: ScopeResult) -> tuple[int, set[str]]:
        with pytest.raises(_RollbackError):
            async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
                stats = await store_results(
                    session,
                    tenant_id=tenant.id,
                    integration_id=integration_id,
                    scan_run_id=run_id,
                    provider="fake",
                    results=[result],
                )
                gone = set(
                    (
                        await session.execute(
                            select(Asset.native_id).where(Asset.deleted_at.is_not(None))
                        )
                    ).scalars()
                )
                outcome = (stats.assets_deleted, gone)
                raise _RollbackError
        return outcome

    # Control: an empty successful scope retires everything it used to hold.
    deleted, gone = await store(ScopeResult(scope=north))
    assert deleted > 1
    web = next(n for n in gone if n.endswith("vm-web-01"))
    # A rejected record with a usable ID is kept...
    deleted, gone = await store(ScopeResult(scope=north, rejected_ids={web}))
    assert web not in gone and len(gone) == deleted
    # ...and one without any usable ID stops the whole scope from deleting.
    deleted, gone = await store(ScopeResult(scope=north, unsafe_to_delete=True))
    assert (deleted, gone) == (0, set())


# ------------------------------------------------------------------ L5 / L2


async def test_read_only_violation_fails_the_whole_scan_and_is_audited(
    db: Database,
    ready_tenant: TenantFixture,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    original = FakeConnector.collect

    async def rogue(self: FakeConnector, scope: Scope) -> AsyncIterator[Any]:
        if scope.id == "fake-acct-001":
            await self._gw.call(ApiCall("fake", "DeleteBucket"))
        async for record in original(self, scope):
            yield record

    monkeypatch.setattr(FakeConnector, "collect", rogue)
    scan = await _reconfigure(db, tenant, integration_id, {"simulate_fixes": ALL_FIXES}, worker)
    assert scan.status == "failed"
    assert scan.scope_errors == [{"scope": "*", "reason": READ_ONLY_REASON}]
    # The healthy regions' data (all fixed) was not stored either.
    assert set(await _finding_statuses(db, tenant)) == {"open"}
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        audit = (
            await session.execute(
                select(AuditLog.outcome, AuditLog.target_id).where(
                    AuditLog.action == "connector.read_only_violation"
                )
            )
        ).all()
    assert [(a.outcome, a.target_id) for a in audit] == [("denied", str(scan.id))]


async def test_empty_discovery_fails_the_scan(
    db: Database,
    ready_tenant: TenantFixture,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    integration_id = await _onboard(db, ready_tenant, worker)

    async def nothing(self: FakeConnector) -> Sequence[Scope]:
        return []

    monkeypatch.setattr(FakeConnector, "discover_scopes", nothing)
    run_id = await _new_run(db, ready_tenant, integration_id, worker, enqueue=True)
    await _drain(worker)
    scan = await _run(db, ready_tenant, run_id)
    assert scan.status == "failed"
    assert scan.scope_errors == [
        {"scope": "*", "reason": "the provider returned no scopes to collect"}
    ]
    assert set(await _finding_statuses(db, ready_tenant)) == {"open"}


# ------------------------------------------------------------------ M4: verify


async def test_verdict_is_dropped_if_the_config_changed_during_the_check(
    db: Database,
    ready_tenant: TenantFixture,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = ready_tenant
    integration_id = await add_fake_integration(db, tenant)
    original = FakeConnector.validate_credentials

    async def racing(self: FakeConnector) -> Any:
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                update(Integration)
                .where(Integration.id == integration_id)
                .values(config={"simulate_fixes": ["encrypt_bucket"]})
            )
        return await original(self)

    monkeypatch.setattr(FakeConnector, "validate_credentials", racing)
    await _drain(worker)
    integration = await _integration(db, tenant, integration_id)
    assert integration.status == "verifying"  # not "connected" for a config nobody checked
    assert await _scan_runs(db, tenant) == 0


async def test_transient_errors_retry_and_only_then_give_up(
    db: Database,
    ready_tenant: TenantFixture,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = ready_tenant

    async def unavailable(self: FakeConnector) -> Any:
        raise TransientError

    monkeypatch.setattr(FakeConnector, "validate_credentials", unavailable)
    integration_id = await add_fake_integration(db, tenant)
    assert await _drain(worker) == 1
    integration = await _integration(db, tenant, integration_id)
    assert integration.status == "verifying"  # the credential wasn't blamed
    async with system_scope(db.factory("skyline_worker")) as session:
        job = (
            await session.execute(select(Job).where(Job.integration_id == integration_id))
        ).scalar_one()
        assert (job.status, job.attempts) == ("queued", 1)
        # Skip the backoff and make the next attempt the last one.
        await session.execute(
            update(Job).where(Job.id == job.id).values(attempts=2, run_at=func.now())
        )
    assert await _drain(worker) == 1
    integration = await _integration(db, tenant, integration_id)
    assert (integration.status, integration.status_detail) == ("access_lost", GAVE_UP_DETAIL)


async def test_reverify_with_a_scan_already_active_still_reconnects(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    await _new_run(db, tenant, integration_id, worker, enqueue=True)
    async with system_scope(db.factory("skyline_worker")) as session:  # another worker has it
        assert await worker.ctx.queue.claim(session, worker_id="other", lease=timedelta(hours=1))
    runs_before = await _scan_runs(db, tenant)
    await _reconfigure(db, tenant, integration_id, {"simulate_fixes": ["encrypt_bucket"]}, worker)
    integration = await _integration(db, tenant, integration_id)
    assert integration.status == "connected"  # not stuck in "verifying"
    assert await _scan_runs(db, tenant) == runs_before  # the active scan will do


# ------------------------------------------------------------------ M5: leases


async def test_a_scan_whose_lease_moved_commits_nothing(
    db: Database, ready_tenant: TenantFixture, worker: Worker, ctx: WorkerContext
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    run_id = await _new_run(db, tenant, integration_id, worker, enqueue=True)
    async with system_scope(db.factory("skyline_worker")) as session:
        job = await ctx.queue.claim(session, worker_id="worker-a", lease=timedelta(minutes=5))
    assert job is not None
    async with system_scope(db.factory("skyline_worker")) as session:  # reaped and re-claimed
        await session.execute(update(Job).where(Job.id == job.id).values(locked_by="worker-b"))
    with pytest.raises(LeaseLostError):
        await run_scan(ctx, job)
    assert (await _run(db, tenant, run_id)).status == "running"  # left for worker-b
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        touched = (
            await session.execute(
                select(func.count()).select_from(Asset).where(Asset.last_seen_scan_id == run_id)
            )
        ).scalar()
    assert touched == 0


class _HeartbeatQueue:
    """Answers heartbeats from a script: an exception, then still held, then lost."""

    def __init__(self, answers: list[bool | Exception]) -> None:
        self.answers = answers
        self.calls = 0

    async def heartbeat(self, session: object, **_: object) -> bool:
        del session
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        if isinstance(answer, Exception):
            raise answer
        return answer


async def test_heartbeat_survives_errors_and_cancels_the_handler_when_the_lease_is_lost(
    ctx: WorkerContext,
) -> None:
    queue = _HeartbeatQueue([RuntimeError("db blip"), True, False])
    worker = Worker(replace(ctx, queue=queue), lease=timedelta(seconds=0.3))  # type: ignore[arg-type]
    handler = asyncio.create_task(asyncio.sleep(30))
    job = ClaimedJob(
        id=uuid4(),
        tenant_id=uuid4(),
        kind=JobKind.SCAN,
        payload=ScanPayload(scan_run_id=uuid4(), integration_id=uuid4()),
        attempts=1,
        max_attempts=3,
        worker_id="w",
    )
    lost = asyncio.Event()
    await asyncio.wait_for(worker._heartbeat(job, handler, lost), timeout=5)
    with contextlib.suppress(asyncio.CancelledError):
        await handler
    assert lost.is_set() and handler.cancelled()
    assert queue.calls == 3


# ------------------------------------------------------------------ L6 / L7


async def test_scheduler_moves_busy_integrations_on(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    await _new_run(db, tenant, integration_id, worker, enqueue=True)  # a scan is active
    async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
        await session.execute(
            update(Integration)
            .where(Integration.id == integration_id)
            .values(next_scan_at=datetime.now(UTC) - timedelta(minutes=1))
        )
    runs_before = await _scan_runs(db, tenant)
    await worker.schedule_once()
    integration = await _integration(db, tenant, integration_id)
    assert integration.next_scan_at is not None
    assert integration.next_scan_at > datetime.now(UTC)  # no longer "due" every minute
    assert await _scan_runs(db, tenant) == runs_before


async def test_sweeper_closes_runs_whose_job_died_unsettled(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    run_id = await _new_run(db, tenant, integration_id, worker, enqueue=True)
    async with system_scope(db.factory("skyline_worker")) as session:
        await session.execute(
            update(Job)
            .where(Job.integration_id == integration_id, Job.status == "queued")
            .values(status="dead", finished_at=func.now())
        )
    assert (await _run(db, tenant, run_id)).status == "queued"
    assert await worker.sweep_once() >= 1
    scan = await _run(db, tenant, run_id)
    assert scan.status == "failed"
    assert await worker.sweep_once() >= 1  # idempotent
    assert (await _run(db, tenant, run_id)).finished_at == scan.finished_at


# ------------------------------------------------------------------ L9 / L10 / L11


async def test_catalogue_drift_is_detected(db: Database, catalogue: Sequence[LoadedCheck]) -> None:
    async with system_scope(db.factory("skyline_worker"), read_only=True) as session:
        assert await catalogue_drift(session, catalogue) == []
        edited = replace(catalogue[0], content_hash=b"\x00" * 32)
        first = catalogue[0].definition.id
        assert await catalogue_drift(session, [edited, *catalogue[1:]]) == [
            f"{first}: differs from the synced version"
        ]
        assert await catalogue_drift(session, catalogue[1:]) == [
            f"{first}: enabled but not shipped"
        ]


async def test_evaluate_only_runs_for_the_latest_stored_scan(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    first = await _latest_run(db, tenant)
    second_id = await _new_run(db, tenant, integration_id, worker, enqueue=True)
    await _drain(worker)

    async def evaluate(scan_run_id: UUID) -> int:
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await worker.ctx.queue.enqueue(
                session,
                tenant_id=tenant.id,
                payload=EvaluatePayload(scan_run_id=scan_run_id, integration_id=integration_id),
            )
        await _drain(worker)
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            return (
                await session.execute(select(func.count()).select_from(FindingEvent))
            ).scalar_one()

    before = await evaluate(first.id)  # stale run: nothing happens
    assert await evaluate(first.id) == before
    assert await evaluate(second_id) == before + 5  # latest run: re-evaluated


async def test_demo_provider_is_refused_unless_enabled(
    db: Database, ready_tenant: TenantFixture, ctx: WorkerContext
) -> None:
    locked_down = Worker(replace(ctx, demo_providers_allowed=False))
    from worker_helpers import drain_jobs

    await drain_jobs(db)
    integration_id = await add_fake_integration(db, ready_tenant)
    await _drain(locked_down)
    integration = await _integration(db, ready_tenant, integration_id)
    assert integration.status == "access_lost"
    assert integration.status_detail == "the demo provider is disabled on this deployment"


# ------------------------------------------------------------------ re-review round 2


async def _audit_actions(db: Database, tenant: TenantFixture, action: str) -> list[Any]:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return list(
            (
                await session.execute(
                    select(AuditLog.target_type, AuditLog.details).where(AuditLog.action == action)
                )
            ).all()
        )


@pytest.mark.parametrize("change", ["delete", "reconfigure"])
async def test_a_scan_stores_nothing_if_the_integration_changed_meanwhile(
    db: Database,
    ready_tenant: TenantFixture,
    worker: Worker,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    from skyline_worker.pipeline.scan import CHANGED_REASON

    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    original = FakeConnector.discover_scopes

    async def changing(self: FakeConnector) -> Sequence[Scope]:
        values: dict[str, Any] = (
            {"deleted_at": func.now(), "status": "disabled", "next_scan_at": None}
            if change == "delete"
            else {"config": {"simulate_fixes": ALL_FIXES}}
        )
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                update(Integration).where(Integration.id == integration_id).values(**values)
            )
        return await original(self)

    monkeypatch.setattr(FakeConnector, "discover_scopes", changing)
    run_id = await _new_run(db, tenant, integration_id, worker, enqueue=True)
    await _drain(worker)
    scan = await _run(db, tenant, run_id)
    assert (scan.status, scan.scope_errors) == (
        "failed",
        [{"scope": "*", "reason": CHANGED_REASON}],
    )
    assert set(await _finding_statuses(db, tenant)) == {"open"}  # the fixes weren't stored
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        touched = (
            await session.execute(
                select(func.count()).select_from(Asset).where(Asset.last_seen_scan_id == run_id)
            )
        ).scalar()
    assert touched == 0
    integration = await _integration(db, tenant, integration_id)
    if change == "delete":
        assert integration.next_scan_at is None  # not revived
    else:
        assert integration.next_scan_at is not None
        assert integration.next_scan_at <= datetime.now(UTC) + timedelta(seconds=5)


async def test_a_violation_during_discovery_is_audited(
    db: Database, ready_tenant: TenantFixture, worker: Worker, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)

    async def rogue(self: FakeConnector) -> Sequence[Scope]:
        await self._gw.call(ApiCall("fake", "DeleteBucket"))
        return []

    monkeypatch.setattr(FakeConnector, "discover_scopes", rogue)
    run_id = await _new_run(db, tenant, integration_id, worker, enqueue=True)
    await _drain(worker)
    assert (await _run(db, tenant, run_id)).scope_errors == [
        {"scope": "*", "reason": READ_ONLY_REASON}
    ]
    rows = await _audit_actions(db, tenant, "connector.read_only_violation")
    assert [r.details["apis"] for r in rows] == [["fake:DeleteBucket"]]


async def test_a_swallowed_violation_still_stops_the_scan(
    db: Database, ready_tenant: TenantFixture, worker: Worker, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = ready_tenant
    integration_id = await _onboard(db, tenant, worker)
    original = FakeConnector.collect

    async def careless(self: FakeConnector, scope: Scope) -> AsyncIterator[Any]:
        with contextlib.suppress(Exception):  # hides the refusal from the runner
            await self._gw.call(ApiCall("fake", "PutBucketPolicy"))
        async for record in original(self, scope):
            yield record

    monkeypatch.setattr(FakeConnector, "collect", careless)
    scan = await _reconfigure(db, tenant, integration_id, {"simulate_fixes": ALL_FIXES}, worker)
    assert (scan.status, scan.scope_errors) == (
        "failed",
        [{"scope": "*", "reason": READ_ONLY_REASON}],
    )
    assert set(await _finding_statuses(db, tenant)) == {"open"}


async def test_a_violation_during_verify_is_audited_and_not_retried(
    db: Database, ready_tenant: TenantFixture, worker: Worker, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = ready_tenant

    original = FakeConnector.validate_credentials

    async def rogue_then_real(self: FakeConnector) -> Any:
        with contextlib.suppress(Exception):
            await self._gw.call(ApiCall("fake", "DeleteEverything"))
        return await original(self)

    monkeypatch.setattr(FakeConnector, "validate_credentials", rogue_then_real)
    integration_id = await add_fake_integration(db, tenant)
    assert await _drain(worker) == 1
    integration = await _integration(db, tenant, integration_id)
    assert integration.status == "verifying"  # the credential isn't blamed
    rows = await _audit_actions(db, tenant, "connector.read_only_violation")
    assert [(r.target_type, r.details["step"]) for r in rows] == [("integration", "verify")]
    async with system_scope(db.factory("skyline_worker")) as session:
        status = (
            await session.execute(select(Job.status).where(Job.integration_id == integration_id))
        ).scalar_one()
    assert status == "failed"  # permanent: not retried
