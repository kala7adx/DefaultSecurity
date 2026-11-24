"""The scan job: collect through the gateway, store, evaluate, update findings (ARCHITECTURE §3)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_connectors.base import AuthenticationError, ConnectorError, ReadOnlyGuardError
from skyline_connectors.runner import ScopeResult, collect_all, safe_reason
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import (
    ActorType,
    AuditOutcome,
    Integration,
    IntegrationStatus,
    ScanRun,
    ScanStatus,
)
from skyline_core.db.tenancy import tenant_scope
from skyline_core.logging import get_logger
from skyline_core.queue import ClaimedJob, ScanPayload
from skyline_worker.context import WorkerContext
from skyline_worker.pipeline.connect import (
    IntegrationSnapshot,
    IntegrationUnavailableError,
    PreparedIntegration,
    load_integration,
    prepare,
    redaction_key,
)
from skyline_worker.pipeline.lifecycle import apply_findings
from skyline_worker.pipeline.store import store_results

_log = get_logger(__name__)

_ACTIVE = (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value)
READ_ONLY_REASON = "the connector attempted an API call outside its read-only allowlist"
CHANGED_REASON = "the integration changed during the scan; a new scan will follow"


class LeaseLostError(RuntimeError):
    """The job's lease moved to another worker; this worker must not commit its results."""


async def _finish(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    scan_run_id: UUID,
    status: ScanStatus,
    stats: dict[str, Any],
    scope_errors: list[dict[str, str]],
) -> bool:
    """Close an active run. A run that is already finished is left alone (returns False)."""
    closed = await session.execute(
        update(ScanRun)
        .where(
            ScanRun.tenant_id == tenant_id,
            ScanRun.id == scan_run_id,
            ScanRun.status.in_(_ACTIVE),
        )
        .values(status=status.value, finished_at=func.now(), stats=stats, scope_errors=scope_errors)
        .returning(ScanRun.id)
    )
    if closed.one_or_none() is None:
        return False
    await record_audit(
        session,
        action=AuditAction.SCAN_FINISHED,
        tenant_id=tenant_id,
        actor_type=ActorType.SYSTEM,
        outcome=AuditOutcome.FAILURE if status is ScanStatus.FAILED else AuditOutcome.SUCCESS,
        target_type="scan_run",
        target_id=scan_run_id,
        details={"status": status.value, "scope_errors": len(scope_errors)},
    )
    return True


async def fail_scan(
    ctx: WorkerContext,
    tenant_id: UUID,
    scan_run_id: UUID,
    reason: str,
    *,
    job: ClaimedJob | None = None,
    access_lost: IntegrationSnapshot | None = None,
) -> bool:
    """Close the run as failed. From inside a handler pass ``job``: a worker whose lease was
    lost must not fail a run (or flag an integration) another worker is now handling.
    ``access_lost`` also marks the integration access_lost, if it is unchanged."""
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        if job is not None and not await ctx.queue.owns(session, job):
            return False
        if access_lost is not None:
            await _mark_access_lost(session, access_lost, reason)
        return await _finish(
            session,
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            status=ScanStatus.FAILED,
            stats={},
            scope_errors=[{"scope": "*", "reason": reason}],
        )


async def _start(
    ctx: WorkerContext, tenant_id: UUID, payload: ScanPayload
) -> tuple[PreparedIntegration, bytes] | None:
    """Mark the run started and prepare the connector. Returns None if there's nothing to do."""
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        run = (
            await session.execute(
                select(ScanRun).where(
                    ScanRun.tenant_id == tenant_id,
                    ScanRun.id == payload.scan_run_id,
                    ScanRun.integration_id == payload.integration_id,
                )
            )
        ).scalar_one_or_none()
        if run is None or run.status not in _ACTIVE:
            return None
        integration = await load_integration(
            session, tenant_id=tenant_id, integration_id=payload.integration_id
        )
        if integration is None or integration.status != IntegrationStatus.CONNECTED.value:
            raise IntegrationUnavailableError("the integration is not connected")
        await session.execute(
            update(ScanRun)
            .where(ScanRun.tenant_id == tenant_id, ScanRun.id == run.id)
            .values(status=ScanStatus.RUNNING.value, started_at=func.now())
        )
        return await prepare(session, ctx, integration), await redaction_key(
            session, ctx, tenant_id
        )


async def _mark_access_lost(
    session: AsyncSession, snapshot: IntegrationSnapshot, detail: str
) -> bool:
    """Flip to access_lost, but only if nobody changed the integration since it was loaded."""
    changed = await session.execute(
        update(Integration)
        .where(*snapshot.unchanged())
        .values(
            status=IntegrationStatus.ACCESS_LOST.value,
            status_detail=detail,
            updated_at=func.now(),
        )
        .returning(Integration.id)
    )
    return changed.one_or_none() is not None


async def _lock_unchanged(session: AsyncSession, snapshot: IntegrationSnapshot) -> bool:
    """Lock the integration row if it is still exactly what this scan collected for.
    Lock order everywhere in the worker: job row (``owns``) first, then integration row."""
    row = await session.execute(
        select(Integration.id).where(*snapshot.unchanged()).with_for_update()
    )
    return row.one_or_none() is not None


async def _read_only_violation(
    ctx: WorkerContext, job: ClaimedJob, apis: list[str], scopes: list[str]
) -> None:
    payload, tenant_id = job.payload, job.tenant_id
    assert isinstance(payload, ScanPayload)  # noqa: S101 - dispatched by kind
    _log.error(
        "read_only_violation_scan_stopped",
        scan_run_id=str(payload.scan_run_id),
        apis=apis[:20],
        scopes=scopes[:20],
    )
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        if not await ctx.queue.owns(session, job):
            raise LeaseLostError
        await record_audit(
            session,
            action=AuditAction.READ_ONLY_VIOLATION,
            tenant_id=tenant_id,
            actor_type=ActorType.SYSTEM,
            outcome=AuditOutcome.DENIED,
            target_type="scan_run",
            target_id=payload.scan_run_id,
            details={
                "integration_id": str(payload.integration_id),
                "apis": apis[:20],
                "scopes": scopes[:20],
            },
        )
        await _finish(
            session,
            tenant_id=tenant_id,
            scan_run_id=payload.scan_run_id,
            status=ScanStatus.FAILED,
            stats={},
            scope_errors=[{"scope": "*", "reason": READ_ONLY_REASON}],
        )


def _scan_status(results: list[ScopeResult]) -> ScanStatus:
    if all(r.ok for r in results):
        return ScanStatus.SUCCEEDED
    if any(r.ok for r in results):
        return ScanStatus.PARTIAL
    return ScanStatus.FAILED


async def _collect(
    ctx: WorkerContext, job: ClaimedJob, prepared: PreparedIntegration, hmac_key: bytes
) -> list[ScopeResult] | None:
    """Validate, discover and collect. Returns None if the scan was closed instead.

    Read-only violations are taken from the gateway's own record, not from exceptions, so a
    connector that catches (and hides) a refused call still stops the whole scan.
    """
    payload = job.payload
    assert isinstance(payload, ScanPayload)  # noqa: S101 - dispatched by kind
    connector, gateway = prepared.spec.build(
        prepared.config, prepared.credentials, ctx.gateway_limits
    )
    results: list[ScopeResult] | None = None
    error: BaseException | None = None
    try:
        if not (await connector.validate_credentials()).ok:
            raise AuthenticationError
        scopes = await connector.discover_scopes()
        results = await collect_all(
            connector,
            scopes,
            provider=prepared.spec.info.provider,
            rules=prepared.spec.redaction,
            hmac_key=hmac_key,
            limits=ctx.runner_limits,
        )
    except ReadOnlyGuardError:
        pass  # recorded by the gateway; handled below
    except Exception as exc:
        # Includes ScopeDiscoveryError: no scopes, too many, duplicates or invalid IDs.
        error = exc
    flagged = [r.scope.id for r in results or [] if r.read_only_violation]
    if gateway.violations or flagged:
        # ADR-0005 layer 3 fired: store nothing from this run, whatever else succeeded.
        apis = sorted({str(api) for api in gateway.violations})
        await _read_only_violation(ctx, job, apis, sorted(flagged))
        return None
    if error is not None:
        if not isinstance(error, ConnectorError | TimeoutError | TypeError):
            raise error  # unexpected: the job retries (no violation was involved)
        lost = prepared.snapshot if isinstance(error, AuthenticationError) else None
        await fail_scan(
            ctx, job.tenant_id, payload.scan_run_id, safe_reason(error), job=job, access_lost=lost
        )
        return None
    return results


async def run_scan(ctx: WorkerContext, job: ClaimedJob) -> None:
    payload = job.payload
    assert isinstance(payload, ScanPayload)  # noqa: S101 - dispatched by kind
    tenant_id = job.tenant_id
    try:
        started = await _start(ctx, tenant_id, payload)
    except IntegrationUnavailableError as exc:
        await fail_scan(ctx, tenant_id, payload.scan_run_id, exc.reason, job=job)
        return
    if started is None:
        return
    prepared, hmac_key = started
    results = await _collect(ctx, job, prepared, hmac_key)
    if results is None:
        return
    failed_scopes = {r.scope.id for r in results if not r.ok}
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        # Locks the job row: if the lease was lost, another worker owns this scan now.
        if not await ctx.queue.owns(session, job):
            raise LeaseLostError
        if not await _lock_unchanged(session, prepared.snapshot):
            # Edited, re-verified or deleted while we collected: these results describe the
            # old configuration (maybe another account). Store nothing; scan again soon.
            await _finish(
                session,
                tenant_id=tenant_id,
                scan_run_id=payload.scan_run_id,
                status=ScanStatus.FAILED,
                stats={},
                scope_errors=[{"scope": "*", "reason": CHANGED_REASON}],
            )
            await session.execute(
                update(Integration)
                .where(
                    Integration.tenant_id == tenant_id,
                    Integration.id == payload.integration_id,
                    Integration.deleted_at.is_(None),
                )
                .values(next_scan_at=func.now())
            )
            return
        store_stats = await store_results(
            session,
            tenant_id=tenant_id,
            integration_id=payload.integration_id,
            scan_run_id=payload.scan_run_id,
            provider=prepared.spec.info.provider,
            results=results,
        )
        lifecycle = await apply_findings(
            session,
            tenant_id=tenant_id,
            integration_id=payload.integration_id,
            scan_run_id=payload.scan_run_id,
            provider=prepared.spec.info.provider,
            checks=ctx.checks,
            failed_scopes=failed_scopes,
            clock=ctx.clock,
        )
        interval: timedelta = prepared.integration.scan_interval
        await session.execute(
            update(Integration)
            .where(Integration.tenant_id == tenant_id, Integration.id == payload.integration_id)
            .values(last_scan_at=func.now(), next_scan_at=func.now() + interval)
        )
        await _finish(
            session,
            tenant_id=tenant_id,
            scan_run_id=payload.scan_run_id,
            status=_scan_status(results),
            stats={"scopes": len(results), **asdict(store_stats), **asdict(lifecycle)},
            scope_errors=[
                {"scope": r.scope.id, "reason": r.error or ""} for r in results if not r.ok
            ],
        )
    _log.info(
        "scan_finished", scan_run_id=str(payload.scan_run_id), failed_scopes=len(failed_scopes)
    )
