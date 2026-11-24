"""The verify_integration job: prove the credential works before an integration is connected.

ADR-0011: no inbound request can mark an integration connected. Only this worker-side check
can, and a newly connected integration gets its first scan straight away.

The verdict is written only if the integration is still exactly what was checked (same
status, config and credential, not deleted): a config edit made while the check ran sends it
back to ``verifying`` and queues a fresh check, and this stale verdict is dropped. Transient
provider errors retry the job; only a rejected credential means ``access_lost``.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, insert, select, update
from sqlalchemy.exc import IntegrityError

from skyline_connectors.base import (
    Connector,
    ConnectorError,
    ReadOnlyGuardError,
    TransientError,
    ValidationResult,
)
from skyline_connectors.runner import clean_text, safe_reason
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import (
    ActorType,
    AuditOutcome,
    Integration,
    IntegrationStatus,
    Job,
    JobKind,
    JobStatus,
    ScanRun,
    ScanTrigger,
)
from skyline_core.db.tenancy import tenant_scope
from skyline_core.logging import get_logger
from skyline_core.queue import ClaimedJob, ScanPayload, VerifyIntegrationPayload
from skyline_worker.context import PermanentJobError, WorkerContext
from skyline_worker.pipeline.connect import (
    IntegrationSnapshot,
    IntegrationUnavailableError,
    load_integration,
    prepare,
)
from skyline_worker.pipeline.scan import READ_ONLY_REASON, LeaseLostError

_log = get_logger(__name__)

GAVE_UP_DETAIL = "the credential check could not be completed; try again later"
VIOLATION_DETAIL = "the check was stopped by Skyline's read-only guard (see the audit log)"


async def _record(
    ctx: WorkerContext, job: ClaimedJob, snapshot: IntegrationSnapshot, *, ok: bool, detail: str
) -> None:
    async with tenant_scope(ctx.session_factory, snapshot.tenant_id) as session:
        if not await ctx.queue.owns(session, job):
            raise LeaseLostError
        status = IntegrationStatus.CONNECTED if ok else IntegrationStatus.ACCESS_LOST
        changed = await session.execute(
            update(Integration)
            .where(*snapshot.unchanged())
            .values(status=status.value, status_detail=detail, updated_at=func.now())
            .returning(Integration.id)
        )
        if changed.one_or_none() is None:
            _log.info("verify_result_discarded", integration_id=str(snapshot.id))
            return
        await record_audit(
            session,
            action=AuditAction.INTEGRATION_VERIFIED
            if ok
            else AuditAction.INTEGRATION_VERIFY_FAILED,
            tenant_id=snapshot.tenant_id,
            actor_type=ActorType.SYSTEM,
            outcome=AuditOutcome.SUCCESS if ok else AuditOutcome.FAILURE,
            target_type="integration",
            target_id=snapshot.id,
            details={"detail": detail},
        )
        if ok and snapshot.status != IntegrationStatus.CONNECTED.value:
            try:
                async with session.begin_nested():
                    scan_run_id = uuid4()
                    await session.execute(
                        insert(ScanRun).values(
                            id=scan_run_id,
                            tenant_id=snapshot.tenant_id,
                            integration_id=snapshot.id,
                            trigger=ScanTrigger.ONBOARDING.value,
                        )
                    )
                    await ctx.queue.enqueue(
                        session,
                        tenant_id=snapshot.tenant_id,
                        payload=ScanPayload(scan_run_id=scan_run_id, integration_id=snapshot.id),
                    )
            except IntegrityError as exc:
                if "uq_jobs_one_active_scan" not in str(exc):
                    raise
                # A scan is already active. If it started before this change it will notice
                # (its snapshot no longer matches) and store nothing; make sure the next
                # scheduler pass scans the new configuration either way.
                _log.info("onboarding_scan_already_active", integration_id=str(snapshot.id))
                await session.execute(
                    update(Integration)
                    .where(
                        Integration.tenant_id == snapshot.tenant_id, Integration.id == snapshot.id
                    )
                    .values(next_scan_at=func.now())
                )


async def run_verify(ctx: WorkerContext, job: ClaimedJob) -> None:
    payload = job.payload
    assert isinstance(payload, VerifyIntegrationPayload)  # noqa: S101 - dispatched by kind
    tenant_id, integration_id = job.tenant_id, payload.integration_id
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        integration = await load_integration(
            session, tenant_id=tenant_id, integration_id=integration_id
        )
        if integration is None or integration.status == IntegrationStatus.DISABLED.value:
            return
        snapshot = IntegrationSnapshot.of(integration)
        try:
            prepared = await prepare(session, ctx, integration)
        except IntegrationUnavailableError as exc:
            prepared, reason = None, exc.reason
    if prepared is None:
        await _record(ctx, job, snapshot, ok=False, detail=reason)
        return
    connector, gateway = prepared.spec.build(
        prepared.config, prepared.credentials, ctx.gateway_limits
    )
    result, error = await _validate(connector)
    if gateway.violations or (result is None and error is None):
        # Our connector's bug, not the customer's credential: audit, leave the status alone,
        # and don't retry. A violation outranks whatever error came with it.
        await _audit_violation(ctx, job, snapshot, sorted({str(a) for a in gateway.violations}))
        raise PermanentJobError(READ_ONLY_REASON)
    if isinstance(error, TransientError | TimeoutError):
        raise error  # the provider was unavailable: retry the job, don't blame the credential
    if isinstance(error, ConnectorError):  # includes AuthenticationError
        await _record(ctx, job, snapshot, ok=False, detail=safe_reason(error))
        return
    if error is not None:
        raise error
    assert result is not None  # noqa: S101 - narrowed by the branches above
    detail = "" if result.ok else clean_text(result.detail or "the credential check failed")
    await _record(ctx, job, snapshot, ok=result.ok, detail=detail)


async def _validate(connector: Connector) -> tuple[ValidationResult | None, Exception | None]:
    """The credential check's result or error. (None, None) means the read-only guard
    stopped it; the gateway's record says which call."""
    try:
        return await connector.validate_credentials(), None
    except ReadOnlyGuardError:
        return None, None
    except Exception as exc:
        return None, exc


async def _audit_violation(
    ctx: WorkerContext, job: ClaimedJob, snapshot: IntegrationSnapshot, apis: list[str]
) -> None:
    _log.error("read_only_violation_verify_stopped", integration_id=str(snapshot.id), apis=apis)
    async with tenant_scope(ctx.session_factory, snapshot.tenant_id) as session:
        if not await ctx.queue.owns(session, job):
            raise LeaseLostError
        await record_audit(
            session,
            action=AuditAction.READ_ONLY_VIOLATION,
            tenant_id=snapshot.tenant_id,
            actor_type=ActorType.SYSTEM,
            outcome=AuditOutcome.DENIED,
            target_type="integration",
            target_id=snapshot.id,
            details={"apis": apis[:20], "step": "verify"},
        )
        await session.execute(
            update(Integration)
            .where(*snapshot.unchanged())
            .values(status_detail=VIOLATION_DETAIL, updated_at=func.now())
        )


async def verify_gave_up(
    ctx: WorkerContext, tenant_id: UUID, integration_id: UUID, *, dead_job_id: UUID
) -> bool:
    """A verify job ran out of attempts: don't leave the integration "verifying" forever,
    unless a newer verify job for it is still waiting to run."""
    newer = (
        select(Job.id)
        .where(
            Job.tenant_id == tenant_id,
            Job.integration_id == integration_id,
            Job.kind == JobKind.VERIFY_INTEGRATION.value,
            Job.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
            Job.id != dead_job_id,
        )
        .exists()
    )
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        changed = await session.execute(
            update(Integration)
            .where(
                Integration.tenant_id == tenant_id,
                Integration.id == integration_id,
                Integration.status == IntegrationStatus.VERIFYING.value,
                Integration.deleted_at.is_(None),
                ~newer,
            )
            .values(
                status=IntegrationStatus.ACCESS_LOST.value,
                status_detail=GAVE_UP_DETAIL,
                updated_at=func.now(),
            )
            .returning(Integration.id)
        )
        if changed.one_or_none() is None:
            return False
        await record_audit(
            session,
            action=AuditAction.INTEGRATION_VERIFY_FAILED,
            tenant_id=tenant_id,
            actor_type=ActorType.SYSTEM,
            outcome=AuditOutcome.FAILURE,
            target_type="integration",
            target_id=integration_id,
            details={"detail": GAVE_UP_DETAIL},
        )
        return True
