"""Evaluate checks on stored assets and move findings through their lifecycle.

new -> still_open -> auto_resolved -> reopened (ARCHITECTURE §3). Rules that keep findings
correct:

* only an explicit ``pass`` resolves a finding; ``error`` and ``not_applicable`` never do;
* only assets seen in *this* scan are evaluated. Anything else is stale (its scope failed, or
  its record was rejected this time) and its findings stay exactly as they are;
* an asset deleted from a successful scope resolves its open findings.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_checks.engine import AssetView, GraphContext, Status, evaluate
from skyline_checks.loader import LoadedCheck
from skyline_core.db.models import (
    Asset,
    Finding,
    FindingEvent,
    FindingEventType,
    FindingStatus,
    Relationship,
    Severity,
)
from skyline_worker.risk import risk_score


@dataclass(slots=True)
class LifecycleStats:
    evaluated: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    not_applicable: int = 0
    new: int = 0
    still_open: int = 0
    reopened: int = 0
    resolved: int = 0
    skipped_stale: int = 0


def _view(asset: Asset) -> AssetView:
    return AssetView(
        id=str(asset.id),
        native_id=asset.native_id,
        resource_type=asset.resource_type,
        provider=asset.provider,
        name=asset.name,
        region=asset.region,
        account_id=asset.account_id,
        tags=asset.tags,
        config=asset.raw_config,
    )


async def load_graph(
    session: AsyncSession, *, tenant_id: UUID, integration_id: UUID, now: datetime
) -> tuple[GraphContext, dict[str, Asset]]:
    assets = (
        (
            await session.execute(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.integration_id == integration_id,
                    Asset.deleted_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    edges = (
        await session.execute(
            select(Relationship.src_asset_id, Relationship.dst_asset_id, Relationship.type).where(
                Relationship.tenant_id == tenant_id,
                Relationship.integration_id == integration_id,
                Relationship.deleted_at.is_(None),
            )
        )
    ).all()
    by_id = {str(a.id): a for a in assets}
    graph = GraphContext(
        [_view(a) for a in assets], [(str(s), str(d), t) for s, d, t in edges], now=now
    )
    return graph, by_id


async def _event(
    session: AsyncSession,
    tenant_id: UUID,
    finding_id: UUID,
    scan_run_id: UUID,
    event: FindingEventType,
) -> None:
    await session.execute(
        insert(FindingEvent).values(
            tenant_id=tenant_id, finding_id=finding_id, scan_run_id=scan_run_id, event=event.value
        )
    )


async def apply_findings(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    integration_id: UUID,
    scan_run_id: UUID,
    provider: str,
    checks: Sequence[LoadedCheck],
    failed_scopes: Collection[str],
    clock: Callable[[], datetime],
) -> LifecycleStats:
    """Evaluate and update findings for one integration in the caller's transaction."""
    stats = LifecycleStats()
    graph, assets = await load_graph(
        session, tenant_id=tenant_id, integration_id=integration_id, now=clock()
    )
    severities = {c.definition.id: c.definition.severity for c in checks}
    existing = {
        (f.asset_id, f.check_id): f
        for f in (
            await session.execute(
                select(Finding).where(
                    Finding.tenant_id == tenant_id, Finding.integration_id == integration_id
                )
            )
        ).scalars()
    }
    for evaluation in evaluate(checks, graph, provider=provider):
        asset = assets[evaluation.asset.id]
        if asset.last_seen_scan_id != scan_run_id or asset.scope_id in failed_scopes:
            stats.skipped_stale += 1
            continue  # not seen in this scan: leave its findings untouched
        stats.evaluated += 1
        status = evaluation.result.status
        finding = existing.get((asset.id, evaluation.check_id))
        if status is Status.FAIL:
            stats.failed += 1
            await _record_failure(
                session,
                stats=stats,
                finding=finding,
                tenant_id=tenant_id,
                integration_id=integration_id,
                scan_run_id=scan_run_id,
                asset_id=asset.id,
                check_id=evaluation.check_id,
                severity=Severity(severities[evaluation.check_id]),
                view=evaluation.asset,
                evidence=dict(evaluation.result.evidence),
            )
        elif status is Status.PASS:
            stats.passed += 1
            if finding is not None and finding.status == FindingStatus.OPEN.value:
                await _resolve(session, finding, scan_run_id)
                stats.resolved += 1
        elif status is Status.ERROR:
            stats.errors += 1
        else:
            stats.not_applicable += 1
    stats.resolved += await _resolve_deleted_assets(
        session,
        tenant_id=tenant_id,
        integration_id=integration_id,
        scan_run_id=scan_run_id,
        failed_scopes=failed_scopes,
    )
    return stats


async def _record_failure(  # noqa: PLR0913 - keyword-only pipeline inputs
    session: AsyncSession,
    *,
    stats: LifecycleStats,
    finding: Finding | None,
    tenant_id: UUID,
    integration_id: UUID,
    scan_run_id: UUID,
    asset_id: UUID,
    check_id: str,
    severity: Severity,
    view: AssetView,
    evidence: dict[str, Any],
) -> None:
    risk = risk_score(severity, view)
    if finding is None:
        finding_id = uuid4()
        await session.execute(
            insert(Finding).values(
                id=finding_id,
                tenant_id=tenant_id,
                integration_id=integration_id,
                asset_id=asset_id,
                check_id=check_id,
                status=FindingStatus.OPEN.value,
                severity=severity.value,
                risk_score=risk,
                evidence=evidence,
                last_scan_run_id=scan_run_id,
            )
        )
        await _event(session, tenant_id, finding_id, scan_run_id, FindingEventType.NEW)
        stats.new += 1
        return
    values: dict[str, Any] = {
        "severity": severity.value,
        "risk_score": risk,
        "evidence": evidence,
        "last_seen_at": func.now(),
        "last_scan_run_id": scan_run_id,
    }
    if finding.status == FindingStatus.RESOLVED.value:
        values |= {
            "status": FindingStatus.OPEN.value,
            "resolved_at": None,
            "reopened_count": Finding.reopened_count + 1,
        }
        event = FindingEventType.REOPENED
        stats.reopened += 1
    else:
        event = FindingEventType.STILL_OPEN
        stats.still_open += 1
    await session.execute(update(Finding).where(Finding.id == finding.id).values(**values))
    await _event(session, tenant_id, finding.id, scan_run_id, event)


async def _resolve(session: AsyncSession, finding: Finding, scan_run_id: UUID) -> None:
    await session.execute(
        update(Finding)
        .where(Finding.id == finding.id)
        .values(
            status=FindingStatus.RESOLVED.value,
            resolved_at=func.now(),
            last_scan_run_id=scan_run_id,
        )
    )
    await _event(
        session, finding.tenant_id, finding.id, scan_run_id, FindingEventType.AUTO_RESOLVED
    )


async def _resolve_deleted_assets(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    integration_id: UUID,
    scan_run_id: UUID,
    failed_scopes: Collection[str],
) -> int:
    gone = select(Asset.id).where(
        Asset.tenant_id == tenant_id,
        Asset.integration_id == integration_id,
        Asset.deleted_at.is_not(None),
        Asset.scope_id.not_in(list(failed_scopes)),
    )
    findings = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.tenant_id == tenant_id,
                    Finding.integration_id == integration_id,
                    Finding.status == FindingStatus.OPEN.value,
                    Finding.asset_id.in_(gone),
                )
            )
        )
        .scalars()
        .all()
    )
    for finding in findings:
        await _resolve(session, finding, scan_run_id)
    return len(findings)
