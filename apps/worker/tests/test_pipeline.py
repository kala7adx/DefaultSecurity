"""End-to-end worker behaviour on the fake connector (the Phase 0 Definition of Done)."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, insert, select, update
from worker_helpers import add_fake_integration

from skyline_checks.engine import Result
from skyline_checks.loader import LoadedCheck
from skyline_core.db.models import (
    Asset,
    AuditLog,
    Finding,
    FindingEvent,
    Integration,
    Job,
    ScanRun,
    Tenant,
)
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.queue import ScanPayload, VerifyIntegrationPayload
from skyline_worker.context import WorkerContext
from skyline_worker.runner import Worker
from testsupport import Database, TenantFixture

pytestmark = pytest.mark.db

ALL_FIXES = ["remove_public_ip", "close_admin_ports", "encrypt_bucket", "enable_mfa", "upgrade_os"]
EXPECTED = {
    ("fake.compute.vm_public_exposure", "vm-web-01"),
    ("fake.network.sg_admin_ports_open", "sg-web-open"),
    ("fake.storage.bucket_encryption", "fake-customer-exports"),
    ("fake.identity.admin_without_mfa", "alice.admin"),
    ("fake.compute.unsupported_os", "vm-web-01"),
}


async def _drain(worker: Worker) -> int:
    ran = 0
    while await worker.run_once():
        ran += 1
    return ran


async def _findings(db: Database, tenant: TenantFixture) -> dict[tuple[str, str], Finding]:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        rows = (
            await session.execute(
                select(Finding, Asset.native_id).join(Asset, Asset.id == Finding.asset_id)
            )
        ).all()
    return {(f.check_id, native.rsplit("/", 1)[1]): f for f, native in rows}


async def _latest_scan(db: Database, tenant: TenantFixture) -> ScanRun:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return (
            await session.execute(select(ScanRun).order_by(ScanRun.created_at.desc()).limit(1))
        ).scalar_one()


async def _rescan(
    db: Database, tenant: TenantFixture, integration_id: UUID, worker: Worker
) -> ScanRun:
    """What POST /scans does: a scan run plus a job, then let the worker run it."""
    scan_run_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(ScanRun).values(
                id=scan_run_id,
                tenant_id=tenant.id,
                integration_id=integration_id,
                trigger="manual",
                requested_by=tenant.admin_id,
            )
        )
        await worker.ctx.queue.enqueue(
            session,
            tenant_id=tenant.id,
            payload=ScanPayload(scan_run_id=scan_run_id, integration_id=integration_id),
        )
    await _drain(worker)
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        return (
            await session.execute(select(ScanRun).where(ScanRun.id == scan_run_id))
        ).scalar_one()


async def _reconfigure(
    db: Database,
    tenant: TenantFixture,
    integration_id: UUID,
    config: dict[str, Any],
    worker: Worker,
) -> ScanRun:
    """What PATCH /integrations does: change config (the DB sends a connected integration back
    to verifying) and enqueue verification; the worker re-verifies and rescans."""
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
    return await _latest_scan(db, tenant)


async def test_onboard_scan_resolve_reopen(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await add_fake_integration(db, tenant)
    assert await _drain(worker) == 2  # verify, then the onboarding scan it enqueues

    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        integration = (
            await session.execute(select(Integration).where(Integration.id == integration_id))
        ).scalar_one()
        asset_count = (await session.execute(select(func.count()).select_from(Asset))).scalar()
    assert integration.status == "connected"
    assert integration.next_scan_at is not None
    assert asset_count == 12

    first = await _latest_scan(db, tenant)
    assert (first.trigger, first.status) == ("onboarding", "succeeded")
    assert first.stats["new"] == 5
    findings = await _findings(db, tenant)
    assert set(findings) == EXPECTED
    assert {f.status for f in findings.values()} == {"open"}
    # Risk: high (7) x internet-facing (1.5) x prod-tagged (1.3) for the public VM.
    assert findings[("fake.compute.vm_public_exposure", "vm-web-01")].risk_score == Decimal("13.65")
    # Raw config was redacted before storage.
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        web = (
            await session.execute(
                select(Asset.raw_config).where(Asset.native_id.like("%vm-web-01"))
            )
        ).scalar_one()
    assert web["user_data"]["redacted"] is True

    second = await _rescan(db, tenant, integration_id, worker)
    assert (second.status, second.stats["still_open"], second.stats["new"]) == ("succeeded", 5, 0)

    fixed = await _reconfigure(db, tenant, integration_id, {"simulate_fixes": ALL_FIXES}, worker)
    assert fixed.trigger == "onboarding"
    assert fixed.stats["resolved"] == 5
    findings = await _findings(db, tenant)
    assert {f.status for f in findings.values()} == {"resolved"}
    assert all(f.resolved_at is not None for f in findings.values())

    reopened = await _reconfigure(db, tenant, integration_id, {"simulate_fixes": []}, worker)
    assert reopened.stats["reopened"] == 5
    findings = await _findings(db, tenant)
    assert {(f.status, f.reopened_count) for f in findings.values()} == {("open", 1)}

    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        events = Counter((await session.execute(select(FindingEvent.event))).scalars())
        audit = set((await session.execute(select(AuditLog.action))).scalars())
    assert events == {"new": 5, "still_open": 5, "auto_resolved": 5, "reopened": 5}
    assert {"integration.verified", "scan.finished"} <= audit


async def test_partial_failure_leaves_failed_scope_untouched(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    tenant = ready_tenant
    integration_id = await add_fake_integration(db, tenant)
    await _drain(worker)
    # Fix everything, but the region holding most resources fails this time.
    scan = await _reconfigure(
        db,
        tenant,
        integration_id,
        {"simulate_fixes": ALL_FIXES, "fail_scopes": ["fake-north-1"]},
        worker,
    )
    assert scan.status == "partial"
    assert scan.scope_errors == [
        {"scope": "fake-north-1", "reason": "region fake-north-1 is unavailable (simulated)"}
    ]
    findings = await _findings(db, tenant)
    # North-region findings stay open; only the identity finding (another scope) resolves.
    assert findings[("fake.identity.admin_without_mfa", "alice.admin")].status == "resolved"
    for key in EXPECTED - {("fake.identity.admin_without_mfa", "alice.admin")}:
        assert findings[key].status == "open", key
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        deleted = (
            await session.execute(
                select(func.count()).select_from(Asset).where(Asset.deleted_at.is_not(None))
            )
        ).scalar()
    assert deleted == 0


async def test_all_scopes_failing_fails_the_scan(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    integration_id = await add_fake_integration(
        db, ready_tenant, {"fail_scopes": ["fake-north-1", "fake-south-1", "fake-acct-001"]}
    )
    await _drain(worker)
    scan = await _latest_scan(db, ready_tenant)
    assert scan.status == "failed"
    assert len(scan.scope_errors) == 3
    assert await _findings(db, ready_tenant) == {}
    del integration_id


async def test_error_results_never_resolve_findings(
    db: Database, ready_tenant: TenantFixture, worker: Worker, ctx: WorkerContext
) -> None:
    tenant = ready_tenant
    integration_id = await add_fake_integration(db, tenant)
    await _drain(worker)

    def broken(_asset: object, _ctx: object) -> Result:
        return Result.error("could not evaluate")

    checks: list[LoadedCheck] = [replace(c, evaluator=broken) for c in ctx.checks]
    broken_worker = Worker(replace(ctx, checks=checks), poll_seconds=0.1)
    scan = await _reconfigure(
        db, tenant, integration_id, {"simulate_fixes": ALL_FIXES}, broken_worker
    )
    assert scan.stats["errors"] > 0
    assert scan.stats["resolved"] == 0
    assert {f.status for f in (await _findings(db, tenant)).values()} == {"open"}


async def test_invalid_config_fails_verification(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    integration_id = await add_fake_integration(db, ready_tenant)
    await _drain(worker)
    before = await _latest_scan(db, ready_tenant)
    after = await _reconfigure(db, ready_tenant, integration_id, {"bogus": 1}, worker)
    assert after.id == before.id  # no new scan for an integration that failed verification
    async with tenant_scope(db.factory("skyline_api"), ready_tenant.id) as session:
        integration = (
            await session.execute(select(Integration).where(Integration.id == integration_id))
        ).scalar_one()
    assert integration.status == "access_lost"
    assert integration.status_detail == "the integration configuration is invalid"
    rescan = await _rescan(db, ready_tenant, integration_id, worker)
    assert rescan.status == "failed"
    assert rescan.scope_errors == [{"scope": "*", "reason": "the integration is not connected"}]


async def test_missing_redaction_key_fails_closed(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    integration_id = await add_fake_integration(db, ready_tenant)
    await _drain(worker)
    async with system_scope(db.factory("skyline_owner")) as session:
        await session.execute(
            update(Tenant).where(Tenant.id == ready_tenant.id).values(redaction_key_secret_id=None)
        )
    scan = await _rescan(db, ready_tenant, integration_id, worker)
    assert scan.status == "failed"
    assert "redaction key" in scan.scope_errors[0]["reason"]


async def test_scheduler_enqueues_due_integrations_once(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    integration_id = await add_fake_integration(db, ready_tenant)
    await _drain(worker)
    async with tenant_scope(db.factory("skyline_worker"), ready_tenant.id) as session:
        await session.execute(
            update(Integration)
            .where(Integration.id == integration_id)
            .values(next_scan_at=datetime.now(UTC) - timedelta(minutes=1))
        )
    assert await worker.schedule_once() >= 1
    assert await worker.schedule_once() == 0  # next_scan_at moved forward
    await _drain(worker)
    scan = await _latest_scan(db, ready_tenant)
    assert (scan.trigger, scan.status) == ("scheduled", "succeeded")


async def test_reaper_fails_scans_whose_worker_died(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    integration_id = await add_fake_integration(db, ready_tenant)
    await _drain(worker)
    scan_run_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), ready_tenant.id) as session:
        await session.execute(
            insert(ScanRun).values(
                id=scan_run_id,
                tenant_id=ready_tenant.id,
                integration_id=integration_id,
                trigger="manual",
            )
        )
        await worker.ctx.queue.enqueue(
            session,
            tenant_id=ready_tenant.id,
            payload=ScanPayload(scan_run_id=scan_run_id, integration_id=integration_id),
            max_attempts=1,
        )
    async with system_scope(db.factory("skyline_worker")) as session:
        claimed = await worker.ctx.queue.claim(
            session, worker_id="dead-worker", lease=timedelta(seconds=-1)
        )
        assert claimed is not None
    reaped = await worker.reap_once()
    assert [r.dead for r in reaped] == [True]
    async with tenant_scope(db.factory("skyline_api"), ready_tenant.id) as session:
        status = (
            await session.execute(select(ScanRun.status).where(ScanRun.id == scan_run_id))
        ).scalar()
    assert status == "failed"


async def test_unknown_scan_run_is_a_no_op(
    db: Database, ready_tenant: TenantFixture, worker: Worker
) -> None:
    integration_id = await add_fake_integration(db, ready_tenant)
    await _drain(worker)
    async with tenant_scope(db.factory("skyline_api"), ready_tenant.id) as session:
        job_id = await worker.ctx.queue.enqueue(
            session,
            tenant_id=ready_tenant.id,
            payload=ScanPayload(scan_run_id=uuid4(), integration_id=integration_id),
        )
    assert await _drain(worker) == 1
    async with system_scope(db.factory("skyline_worker")) as session:
        status = (await session.execute(select(Job.status).where(Job.id == job_id))).scalar()
    assert status == "succeeded"
