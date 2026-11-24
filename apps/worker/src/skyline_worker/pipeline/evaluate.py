"""The evaluate job: re-run checks on stored data without calling any provider.

Only the integration's latest scan that stored data (succeeded or partial) is re-evaluated:
an older run, or a run that failed as a whole, describes data that is no longer current.
"""

from __future__ import annotations

from sqlalchemy import select

from skyline_core.db.models import Integration, ScanRun, ScanStatus
from skyline_core.db.tenancy import tenant_scope
from skyline_core.logging import get_logger
from skyline_core.queue import ClaimedJob, EvaluatePayload
from skyline_worker.context import WorkerContext
from skyline_worker.pipeline.lifecycle import apply_findings
from skyline_worker.pipeline.scan import LeaseLostError

_log = get_logger(__name__)

_STORED = (ScanStatus.SUCCEEDED.value, ScanStatus.PARTIAL.value)


async def run_evaluate(ctx: WorkerContext, job: ClaimedJob) -> None:
    payload = job.payload
    assert isinstance(payload, EvaluatePayload)  # noqa: S101 - dispatched by kind
    tenant_id = job.tenant_id
    async with tenant_scope(ctx.session_factory, tenant_id) as session:
        if not await ctx.queue.owns(session, job):
            raise LeaseLostError
        # Lock the integration first (as the scan's final transaction does), so a scan and a
        # re-evaluation never write the same findings at once; then pick "latest".
        provider = (
            await session.execute(
                select(Integration.provider)
                .where(
                    Integration.tenant_id == tenant_id,
                    Integration.id == payload.integration_id,
                    Integration.deleted_at.is_(None),
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        latest = (
            await session.execute(
                select(ScanRun)
                .where(
                    ScanRun.tenant_id == tenant_id,
                    ScanRun.integration_id == payload.integration_id,
                    ScanRun.status.in_(_STORED),
                )
                .order_by(ScanRun.finished_at.desc().nulls_last(), ScanRun.id)
                .limit(1)
            )
        ).scalar_one_or_none()
        if latest is None or provider is None or latest.id != payload.scan_run_id:
            _log.info("evaluate_skipped", scan_run_id=str(payload.scan_run_id))
            return
        errors = [e for e in latest.scope_errors if isinstance(e, dict)]
        failed = {str(e.get("scope")) for e in errors}
        if "*" in failed:  # defensive: a whole-run failure never stores data
            return
        # Scopes that failed in that scan keep their findings untouched here too.
        await apply_findings(
            session,
            tenant_id=tenant_id,
            integration_id=payload.integration_id,
            scan_run_id=payload.scan_run_id,
            provider=provider,
            checks=ctx.checks,
            failed_scopes=failed,
            clock=ctx.clock,
        )
