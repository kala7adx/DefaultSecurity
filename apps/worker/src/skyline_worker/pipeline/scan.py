"""The scan job: collect through the gateway, store, evaluate, update findings (ARCHITECTURE §3)."""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_connectors.base import AuthenticationError, ConnectorError
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
    IntegrationUnavailableError,
    PreparedIntegration,
    load_integration,
    prepare,
    redaction_key,
)
from skyline_worker.pipeline.lifecycle import apply_findings
from skyline_worker.pipeline.store import store_results

_log = get_logger(__name__)


async def _finish(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    scan_run_id: UUID,
    status: ScanStatus,
    stats: dict[str, Any],
    scope_errors: list[dict[str, str]],
) -> None:
    await session.execute(
        update(ScanRun)
        .where(ScanRun.tenant_id == tenant_id, ScanRun.id == scan_run_id)
        .values(status=status.value, finished_at=func.now(), stats=stats, scope_errors=scope_errors)
    )
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


async def fail_scan(ctx: WorkerContext, tenant_id: UUID, scan_run_id: UUID, reason: str) -> None:
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        await _finish(
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
        if run is None or run.status not in {ScanStatus.QUEUED.value, ScanStatus.RUNNING.value}:
            return None
        integration = await load_integration(
            session, tenant_id=tenant_id, integration_id=payload.integration_id
        )
        if integration is None or integration.status != IntegrationStatus.CONNECTED.value:
            raise IntegrationUnavailableError("the integration is not connected")
        await session.execute(
            update(ScanRun)
            .where(ScanRun.id == run.id)
            .values(status=ScanStatus.RUNNING.value, started_at=func.now())
        )
        return await prepare(session, ctx, integration), await redaction_key(
            session, ctx, tenant_id
        )


async def _mark_access_lost(ctx: WorkerContext, tenant_id: UUID, integration_id: UUID) -> None:
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        await session.execute(
            update(Integration)
            .where(Integration.tenant_id == tenant_id, Integration.id == integration_id)
            .values(
                status=IntegrationStatus.ACCESS_LOST.value,
                status_detail="the provider rejected the credentials",
                updated_at=func.now(),
            )
        )


def _scan_status(results: list[ScopeResult]) -> ScanStatus:
    if all(r.ok for r in results):
        return ScanStatus.SUCCEEDED
    if any(r.ok for r in results):
        return ScanStatus.PARTIAL
    return ScanStatus.FAILED


async def run_scan(ctx: WorkerContext, job: ClaimedJob) -> None:
    payload = job.payload
    assert isinstance(payload, ScanPayload)  # noqa: S101 - dispatched by kind
    tenant_id = job.tenant_id
    try:
        started = await _start(ctx, tenant_id, payload)
    except IntegrationUnavailableError as exc:
        await fail_scan(ctx, tenant_id, payload.scan_run_id, exc.reason)
        return
    if started is None:
        return
    prepared, hmac_key = started
    connector, _gateway = prepared.spec.build(
        prepared.config, prepared.credentials, ctx.gateway_limits
    )
    try:
        if not (await connector.validate_credentials()).ok:
            raise AuthenticationError
        scopes = await connector.discover_scopes()
    except AuthenticationError as exc:
        await _mark_access_lost(ctx, tenant_id, payload.integration_id)
        await fail_scan(ctx, tenant_id, payload.scan_run_id, exc.safe_message)
        return
    except (ConnectorError, TimeoutError, TypeError) as exc:
        await fail_scan(ctx, tenant_id, payload.scan_run_id, safe_reason(exc))
        return
    results = await collect_all(
        connector,
        scopes,
        provider=prepared.spec.info.provider,
        rules=prepared.spec.redaction,
        hmac_key=hmac_key,
        limits=ctx.runner_limits,
    )
    failed_scopes = {r.scope.id for r in results if not r.ok}
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
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
