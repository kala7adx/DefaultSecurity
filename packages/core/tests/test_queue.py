"""Job queue: claiming, leases, retries, dead-lettering and the one-active-scan rule."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from skyline_core.db.models import Integration, Job, JobStatus
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.queue import (
    InvalidJobError,
    PostgresJobQueue,
    ScanPayload,
    VerifyIntegrationPayload,
    decode_payload,
    retry_delay,
    sanitise_error,
)
from testsupport import Database, TenantFixture

pytestmark = pytest.mark.db

LEASE = timedelta(seconds=60)


async def _integration(db: Database, tenant: TenantFixture) -> UUID:
    integration_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(Integration).values(
                id=integration_id,
                tenant_id=tenant.id,
                provider="fake",
                name="q",
                status="verifying",
            )
        )
    return integration_id


async def _drain(db: Database) -> None:
    """Mark leftovers from other tests as finished so claims here are deterministic."""
    async with system_scope(db.factory("skyline_worker")) as session:
        await session.execute(
            update(Job)
            .where(Job.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]))
            .values(status=JobStatus.SUCCEEDED.value)
        )


async def test_enqueue_claim_complete(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    queue = PostgresJobQueue()
    integration_id = await _integration(db, tenant)
    payload = VerifyIntegrationPayload(integration_id=integration_id)
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        job_id = await queue.enqueue(session, tenant_id=tenant.id, payload=payload)
    worker = db.factory("skyline_worker")
    async with system_scope(worker) as session:
        job = await queue.claim(session, worker_id="w1", lease=LEASE)
    assert job is not None
    assert (job.id, job.tenant_id, job.payload, job.attempts) == (job_id, tenant.id, payload, 1)
    async with system_scope(worker) as session:
        assert await queue.heartbeat(session, job_id=job.id, worker_id="w1", lease=LEASE)
        assert not await queue.heartbeat(session, job_id=job.id, worker_id="other", lease=LEASE)
        await queue.complete(session, job_id=job.id, worker_id="w1")
    async with system_scope(worker) as session:
        status = (await session.execute(select(Job.status).where(Job.id == job.id))).scalar()
        assert status == "succeeded"
        assert await queue.claim(session, worker_id="w1", lease=LEASE) is None


async def test_concurrent_claims_never_share_a_job(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    queue = PostgresJobQueue()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        for _ in range(5):
            await queue.enqueue(
                session,
                tenant_id=tenant.id,
                payload=VerifyIntegrationPayload(integration_id=await _integration(db, tenant)),
            )
    worker = db.factory("skyline_worker")

    async def claim(n: int) -> UUID | None:
        async with system_scope(worker) as session:
            job = await queue.claim(session, worker_id=f"w{n}", lease=LEASE)
            await asyncio.sleep(0.05)  # hold the row lock while others try
            return job.id if job else None

    claimed = [j for j in await asyncio.gather(*(claim(n) for n in range(5))) if j]
    assert len(claimed) == len(set(claimed)) == 5


async def test_retry_then_dead_letter(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    queue = PostgresJobQueue()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        job_id = await queue.enqueue(
            session,
            tenant_id=tenant.id,
            payload=VerifyIntegrationPayload(integration_id=await _integration(db, tenant)),
            max_attempts=2,
        )
    worker = db.factory("skyline_worker")
    for attempt in (1, 2):
        async with system_scope(worker) as session:
            await session.execute(update(Job).where(Job.id == job_id).values(run_at=Job.created_at))
            job = await queue.claim(session, worker_id="w", lease=LEASE)
            assert job is not None
            assert job.attempts == attempt
            retried = await queue.fail(
                session, job=job, worker_id="w", error="boom", retryable=True
            )
            assert retried is (attempt == 1)
    async with system_scope(worker) as session:
        row = (
            await session.execute(select(Job.status, Job.last_error).where(Job.id == job_id))
        ).one()
    assert (row.status, row.last_error) == ("dead", "boom")


async def test_non_retryable_failure_is_final(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    queue = PostgresJobQueue()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        job_id = await queue.enqueue(
            session,
            tenant_id=tenant.id,
            payload=VerifyIntegrationPayload(integration_id=await _integration(db, tenant)),
        )
    async with system_scope(db.factory("skyline_worker")) as session:
        job = await queue.claim(session, worker_id="w", lease=LEASE)
        assert job is not None
        assert not await queue.fail(session, job=job, worker_id="w", error="bad", retryable=False)
        status = (await session.execute(select(Job.status).where(Job.id == job_id))).scalar()
    assert status == "failed"


async def test_reaper_requeues_expired_leases(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    queue = PostgresJobQueue()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        job_id = await queue.enqueue(
            session,
            tenant_id=tenant.id,
            payload=VerifyIntegrationPayload(integration_id=await _integration(db, tenant)),
            max_attempts=1,
        )
    worker = db.factory("skyline_worker")
    async with system_scope(worker) as session:
        job = await queue.claim(session, worker_id="w", lease=timedelta(seconds=-1))
        assert job is not None
    async with system_scope(worker) as session:
        reaped = await queue.reap_expired(session)
    assert [(r.id, r.dead) for r in reaped] == [(job_id, True)]
    assert reaped[0].payload is not None


async def test_invalid_payload_is_dead_lettered(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    async with system_scope(db.factory("skyline_worker")) as session:
        job_id = uuid4()
        await session.execute(
            insert(Job).values(
                id=job_id, tenant_id=tenant.id, kind="scan", payload={"evil": "__import__('os')"}
            )
        )
        assert await PostgresJobQueue().claim(session, worker_id="w", lease=LEASE) is None
        status = (await session.execute(select(Job.status).where(Job.id == job_id))).scalar()
    assert status == "dead"


async def test_only_one_active_scan_per_integration(db: Database, tenant: TenantFixture) -> None:
    queue = PostgresJobQueue()
    integration_id = await _integration(db, tenant)
    payload = ScanPayload(scan_run_id=uuid4(), integration_id=integration_id)
    api = db.factory("skyline_api")
    async with tenant_scope(api, tenant.id) as session:
        await queue.enqueue(session, tenant_id=tenant.id, payload=payload)
    with pytest.raises(IntegrityError):
        async with tenant_scope(api, tenant.id) as session:
            await queue.enqueue(session, tenant_id=tenant.id, payload=payload)


def test_decode_payload_rejects_unknown_kinds_and_fields() -> None:
    with pytest.raises(InvalidJobError):
        decode_payload("rm_rf", {})
    with pytest.raises(InvalidJobError):
        decode_payload("verify_integration", {"integration_id": str(uuid4()), "extra": 1})


def test_retry_delay_is_bounded() -> None:
    for attempts in range(1, 30):
        delay = retry_delay(attempts)
        assert timedelta(0) < delay <= timedelta(minutes=15)


def test_sanitise_error_redacts_and_truncates() -> None:
    fake_key = "AKIA" + "X" * 16
    message = sanitise_error(RuntimeError(f"failed with {fake_key} " + "x" * 1000))
    assert fake_key not in message
    assert message.startswith("RuntimeError")
    assert len(message) <= 500


async def test_reaper_dead_letters_undecodable_jobs(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    job_id = uuid4()
    async with system_scope(db.factory("skyline_worker")) as session:
        await session.execute(
            insert(Job).values(id=job_id, tenant_id=tenant.id, kind="scan", payload={"x": 1})
        )
        await session.execute(
            update(Job)
            .where(Job.id == job_id)
            .values(status="running", lease_expires_at=Job.created_at, locked_by="gone")
        )
    async with system_scope(db.factory("skyline_worker")) as session:
        reaped = await PostgresJobQueue().reap_expired(session)
        status = (await session.execute(select(Job.status).where(Job.id == job_id))).scalar()
    assert [(r.id, r.dead, r.payload, r.kind) for r in reaped] == [(job_id, True, None, None)]
    assert status == "dead"


async def test_fail_redacts_errors_itself(db: Database, tenant: TenantFixture) -> None:
    await _drain(db)
    queue = PostgresJobQueue()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        job_id = await queue.enqueue(
            session,
            tenant_id=tenant.id,
            payload=VerifyIntegrationPayload(integration_id=await _integration(db, tenant)),
        )
    fake_key = "AKIA" + "Y" * 16
    async with system_scope(db.factory("skyline_worker")) as session:
        job = await queue.claim(session, worker_id="w", lease=LEASE)
        assert job is not None
        await queue.fail(
            session, job=job, worker_id="w", error=f"client_secret={fake_key}", retryable=False
        )
        error = (await session.execute(select(Job.last_error).where(Job.id == job_id))).scalar()
    assert error is not None
    assert fake_key not in error


async def test_payload_must_be_an_object(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(IntegrityError):
        async with system_scope(db.factory("skyline_worker")) as session:
            await session.execute(
                insert(Job).values(id=uuid4(), tenant_id=tenant.id, kind="scan", payload=[1, 2])
            )


async def test_indexed_integration_must_match_the_payload(
    db: Database, tenant: TenantFixture
) -> None:
    integration_id = await _integration(db, tenant)
    with pytest.raises(IntegrityError):
        async with system_scope(db.factory("skyline_worker")) as session:
            await session.execute(
                insert(Job).values(
                    id=uuid4(),
                    tenant_id=tenant.id,
                    kind="verify_integration",
                    integration_id=integration_id,
                    payload={"integration_id": str(uuid4())},
                )
            )
