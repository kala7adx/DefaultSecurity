"""The verify_integration job: prove the credential works before an integration is connected.

ADR-0011: no inbound request can mark an integration connected. Only this worker-side check
can, and a newly connected integration gets its first scan straight away.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, insert, update

from skyline_connectors.base import ConnectorError
from skyline_connectors.runner import safe_reason
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import (
    ActorType,
    AuditOutcome,
    Integration,
    IntegrationStatus,
    ScanRun,
    ScanTrigger,
)
from skyline_core.db.tenancy import tenant_scope
from skyline_core.queue import ClaimedJob, ScanPayload, VerifyIntegrationPayload
from skyline_worker.context import WorkerContext
from skyline_worker.pipeline.connect import IntegrationUnavailableError, load_integration, prepare


async def _record(
    ctx: WorkerContext, tenant_id: UUID, integration_id: UUID, *, ok: bool, detail: str, first: bool
) -> None:
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        values: dict[str, object] = {"status_detail": detail, "updated_at": func.now()}
        values["status"] = (
            IntegrationStatus.CONNECTED.value if ok else IntegrationStatus.ACCESS_LOST.value
        )
        await session.execute(
            update(Integration)
            .where(Integration.tenant_id == tenant_id, Integration.id == integration_id)
            .values(**values)
        )
        await record_audit(
            session,
            action=AuditAction.INTEGRATION_VERIFIED
            if ok
            else AuditAction.INTEGRATION_VERIFY_FAILED,
            tenant_id=tenant_id,
            actor_type=ActorType.SYSTEM,
            outcome=AuditOutcome.SUCCESS if ok else AuditOutcome.FAILURE,
            target_type="integration",
            target_id=integration_id,
            details={"detail": detail},
        )
        if ok and first:
            scan_run_id = uuid4()
            await session.execute(
                insert(ScanRun).values(
                    id=scan_run_id,
                    tenant_id=tenant_id,
                    integration_id=integration_id,
                    trigger=ScanTrigger.ONBOARDING.value,
                )
            )
            await ctx.queue.enqueue(
                session,
                tenant_id=tenant_id,
                payload=ScanPayload(scan_run_id=scan_run_id, integration_id=integration_id),
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
        first = integration.status != IntegrationStatus.CONNECTED.value
        reason = ""
        try:
            prepared = await prepare(session, ctx, integration)
        except IntegrationUnavailableError as exc:
            prepared, reason = None, exc.reason
    if prepared is None:
        await _record(ctx, tenant_id, integration_id, ok=False, detail=reason, first=first)
        return
    connector, _ = prepared.spec.build(prepared.config, prepared.credentials, ctx.gateway_limits)
    try:
        result = await connector.validate_credentials()
    except (ConnectorError, TimeoutError) as exc:
        await _record(
            ctx, tenant_id, integration_id, ok=False, detail=safe_reason(exc), first=first
        )
        return
    detail = "" if result.ok else (result.detail or "the credential check failed")
    await _record(ctx, tenant_id, integration_id, ok=result.ok, detail=detail, first=first)
