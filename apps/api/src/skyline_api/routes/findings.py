"""Findings: filtered list, detail with evidence and framework mappings, summary counts.

"Muted" is computed at query time (open + an active, unexpired exception), so mutes expire on
their own with no background job (ARCHITECTURE §3).
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import ColumnElement, Select, and_, exists, func, or_, select

from skyline_api.auth import Principal, TenantDbDep, require
from skyline_api.errors import not_found
from skyline_api.rbac import Permission
from skyline_api.schemas import (
    ControlRefOut,
    ExceptionOut,
    FindingDetailOut,
    FindingEventOut,
    FindingOut,
    Page,
    SafeText,
    SummaryOut,
)
from skyline_core.db.models import (
    Asset,
    Check,
    CheckControlMap,
    Control,
    Finding,
    FindingEvent,
    FindingException,
    FindingStatus,
    Framework,
    Integration,
    Severity,
)

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

StatusFilter = Literal["open", "muted", "resolved", "all"]

if TYPE_CHECKING:
    FindingQuery = Select[Finding, str, str | None, str, bool]


def exception_matches() -> ColumnElement[bool]:
    """An active exception covers this finding (by finding, check, asset or check-on-asset)."""
    e = FindingException
    return and_(
        e.tenant_id == Finding.tenant_id,
        e.revoked_at.is_(None),
        e.expires_at > func.now(),
        or_(
            and_(e.scope_type == "finding", e.finding_id == Finding.id),
            and_(e.scope_type == "check", e.check_id == Finding.check_id),
            and_(e.scope_type == "asset", e.asset_id == Finding.asset_id),
            and_(
                e.scope_type == "check_on_asset",
                e.check_id == Finding.check_id,
                e.asset_id == Finding.asset_id,
            ),
        ),
    )


MUTED: ColumnElement[bool] = and_(
    Finding.status == FindingStatus.OPEN.value, exists().where(exception_matches())
)


def _base(tenant_id: UUID) -> FindingQuery:
    return (
        select(
            Finding,
            Check.title,
            Asset.name.label("asset_name"),
            Asset.resource_type,
            MUTED.label("muted"),
        )
        .join(Asset, and_(Asset.tenant_id == Finding.tenant_id, Asset.id == Finding.asset_id))
        .join(Check, Check.id == Finding.check_id)
        .join(
            Integration,
            and_(
                Integration.tenant_id == Finding.tenant_id, Integration.id == Finding.integration_id
            ),
        )
        .where(Finding.tenant_id == tenant_id, Integration.deleted_at.is_(None))
    )


def _with_status(query: FindingQuery, status: StatusFilter) -> FindingQuery:
    if status == "open":
        return query.where(Finding.status == FindingStatus.OPEN.value, ~MUTED)
    if status == "muted":
        return query.where(MUTED)
    if status == "resolved":
        return query.where(Finding.status == FindingStatus.RESOLVED.value)
    return query


def _in_framework(framework_id: str) -> ColumnElement[bool]:
    return exists().where(
        CheckControlMap.check_id == Finding.check_id,
        CheckControlMap.control_id == Control.id,
        Control.framework_id == framework_id,
    )


def _out(row: Any) -> FindingOut:
    f: Finding = row.Finding
    return FindingOut(
        id=f.id,
        check_id=f.check_id,
        title=row.title,
        severity=f.severity,
        status=f.status,
        muted=bool(row.muted),
        risk_score=f.risk_score,
        asset_id=f.asset_id,
        asset_name=row.asset_name,
        resource_type=row.resource_type,
        integration_id=f.integration_id,
        first_seen_at=f.first_seen_at,
        last_seen_at=f.last_seen_at,
        resolved_at=f.resolved_at,
        reopened_count=f.reopened_count,
    )


@router.get("")
async def list_findings(  # noqa: PLR0913, PLR0917 - query filters
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FINDINGS_READ))],
    status: StatusFilter = "open",
    severity: Annotated[list[Severity] | None, Query()] = None,
    check_id: Annotated[SafeText | None, Query(max_length=120)] = None,
    integration_id: UUID | None = None,
    asset_id: UUID | None = None,
    provider: Annotated[SafeText | None, Query(max_length=32)] = None,
    framework: Annotated[SafeText | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> Page[FindingOut]:
    query = _with_status(_base(tdb.principal.tenant_id), status)
    if severity:
        query = query.where(Finding.severity.in_([s.value for s in severity]))
    if check_id:
        query = query.where(Finding.check_id == check_id)
    if integration_id:
        query = query.where(Finding.integration_id == integration_id)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if provider:
        query = query.where(Check.provider == provider)
    if framework:
        query = query.where(_in_framework(framework))
    async with tdb.transaction() as db:
        total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        rows = await db.execute(
            query.order_by(Finding.risk_score.desc(), Finding.last_seen_at.desc(), Finding.id)
            .limit(limit)
            .offset(offset)
        )
        return Page(items=[_out(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/summary")
async def summary(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FINDINGS_READ))],
) -> SummaryOut:
    base = _base(tdb.principal.tenant_id).subquery()
    async with tdb.transaction() as db:
        rows = (
            await db.execute(
                select(base.c.status, base.c.severity, base.c.muted, func.count()).group_by(
                    base.c.status, base.c.severity, base.c.muted
                )
            )
        ).all()
        frameworks = (
            await db.execute(
                select(Control.framework_id, func.count(func.distinct(Finding.id)))
                .select_from(Finding)
                .join(CheckControlMap, CheckControlMap.check_id == Finding.check_id)
                .join(Control, Control.id == CheckControlMap.control_id)
                .join(
                    Integration,
                    and_(
                        Integration.tenant_id == Finding.tenant_id,
                        Integration.id == Finding.integration_id,
                    ),
                )
                .where(
                    Finding.tenant_id == tdb.principal.tenant_id,
                    Finding.status == FindingStatus.OPEN.value,
                    Integration.deleted_at.is_(None),
                    ~MUTED,
                )
                .group_by(Control.framework_id)
            )
        ).all()
    open_by: Counter[str] = Counter()
    muted = resolved = 0
    for status, severity, is_muted, count in rows:
        if status == FindingStatus.RESOLVED.value:
            resolved += count
        elif is_muted:
            muted += count
        else:
            open_by[severity] += count
    return SummaryOut(
        open_by_severity={s.value: open_by.get(s.value, 0) for s in Severity},
        open_total=sum(open_by.values()),
        muted=muted,
        resolved=resolved,
        by_framework={row[0]: int(row[1]) for row in frameworks},
    )


@router.get("/{finding_id}")
async def get_finding(
    finding_id: UUID,
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FINDINGS_READ))],
) -> FindingDetailOut:
    tenant_id = tdb.principal.tenant_id
    async with tdb.transaction() as db:
        row = (await db.execute(_base(tenant_id).where(Finding.id == finding_id))).first()
        if row is None:
            raise not_found("finding")
        finding: Finding = row.Finding
        meta = (
            await db.execute(select(Check.meta).where(Check.id == finding.check_id))
        ).scalar_one()
        controls = (
            await db.execute(
                select(
                    Framework.id,
                    Framework.name,
                    Control.ref,
                    Control.title,
                    CheckControlMap.reviewed,
                )
                .join(Control, Control.framework_id == Framework.id)
                .join(CheckControlMap, CheckControlMap.control_id == Control.id)
                .where(CheckControlMap.check_id == finding.check_id)
                .order_by(Framework.id, Control.ref)
            )
        ).all()
        events = (
            await db.execute(
                select(FindingEvent)
                .where(FindingEvent.tenant_id == tenant_id, FindingEvent.finding_id == finding_id)
                .order_by(FindingEvent.at.desc(), FindingEvent.id.desc())
                .limit(50)
            )
        ).scalars()
        exception = (
            await db.execute(
                select(FindingException)
                .where(
                    FindingException.tenant_id == tenant_id,
                    exists()
                    .where(exception_matches(), Finding.id == finding_id)
                    .correlate(FindingException),
                )
                .order_by(FindingException.expires_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        return FindingDetailOut(
            **_out(row).model_dump(),
            evidence=finding.evidence,
            check={
                k: meta.get(k)
                for k in ("description", "rationale", "remediation", "references", "tags")
            },
            controls=[
                ControlRefOut(
                    framework_id=c[0], framework_name=c[1], ref=c[2], title=c[3], reviewed=c[4]
                )
                for c in controls
            ],
            events=[FindingEventOut.model_validate(e) for e in events],
            active_exception=ExceptionOut.model_validate(exception) if exception else None,
        )
