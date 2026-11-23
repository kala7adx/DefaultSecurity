"""The evaluate job: re-run checks on stored data without calling any provider."""

from __future__ import annotations

from sqlalchemy import select

from skyline_core.db.models import Integration, ScanRun
from skyline_core.db.tenancy import tenant_scope
from skyline_core.queue import ClaimedJob, EvaluatePayload
from skyline_worker.context import WorkerContext
from skyline_worker.pipeline.lifecycle import apply_findings


async def run_evaluate(ctx: WorkerContext, job: ClaimedJob) -> None:
    payload = job.payload
    assert isinstance(payload, EvaluatePayload)  # noqa: S101 - dispatched by kind
    async with tenant_scope(ctx.session_factory, job.tenant_id) as session:
        run = (
            await session.execute(
                select(ScanRun).where(
                    ScanRun.tenant_id == job.tenant_id,
                    ScanRun.id == payload.scan_run_id,
                    ScanRun.integration_id == payload.integration_id,
                )
            )
        ).scalar_one_or_none()
        provider = (
            await session.execute(
                select(Integration.provider).where(
                    Integration.tenant_id == job.tenant_id,
                    Integration.id == payload.integration_id,
                )
            )
        ).scalar_one_or_none()
        if run is None or provider is None:
            return
        # Scopes that failed in that scan keep their findings untouched here too.
        failed = {str(e.get("scope")) for e in run.scope_errors if isinstance(e, dict)}
        await apply_findings(
            session,
            tenant_id=job.tenant_id,
            integration_id=payload.integration_id,
            scan_run_id=payload.scan_run_id,
            provider=provider,
            checks=ctx.checks,
            failed_scopes=failed,
            clock=ctx.clock,
        )
