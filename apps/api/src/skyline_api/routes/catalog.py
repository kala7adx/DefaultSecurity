"""Check catalogue, frameworks and controls, the audit log, and health probes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text

from skyline_api.auth import Principal, ServicesDep, TenantDbDep, require
from skyline_api.errors import not_found
from skyline_api.rbac import Permission
from skyline_api.schemas import AuditOut, CheckOut, ControlOut, FrameworkOut, Page, SafeText
from skyline_core.db.migrate import current_revision, head_revision
from skyline_core.db.models import AuditLog, Check, CheckControlMap, Control, Framework, Severity

router = APIRouter(prefix="/api/v1", tags=["catalogue"])
health = APIRouter(tags=["health"])


@router.get("/checks")
async def list_checks(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FRAMEWORKS_READ))],
) -> list[CheckOut]:
    async with tdb.transaction() as db:
        rows = (await db.execute(select(Check).order_by(Check.id))).scalars()
        return [
            CheckOut(
                id=r.id,
                version=r.version,
                provider=r.provider,
                severity=Severity(r.severity),
                title=r.title,
                enabled=r.enabled,
            )
            for r in rows
        ]


@router.get("/frameworks")
async def list_frameworks(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FRAMEWORKS_READ))],
) -> list[FrameworkOut]:
    async with tdb.transaction() as db:
        rows = (await db.execute(select(Framework).order_by(Framework.id))).scalars()
        return [FrameworkOut.model_validate(r) for r in rows]


@router.get("/frameworks/{framework_id}/controls")
async def list_controls(
    framework_id: Annotated[SafeText, Path(max_length=64)],
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FRAMEWORKS_READ))],
) -> list[ControlOut]:
    async with tdb.transaction() as db:
        if (
            await db.execute(select(Framework.id).where(Framework.id == framework_id))
        ).first() is None:
            raise not_found("framework")
        controls = (
            (
                await db.execute(
                    select(Control)
                    .where(Control.framework_id == framework_id)
                    .order_by(Control.ref)
                )
            )
            .scalars()
            .all()
        )
        maps = (
            await db.execute(
                select(CheckControlMap.control_id, CheckControlMap.check_id).where(
                    CheckControlMap.control_id.in_([c.id for c in controls])
                )
            )
        ).all()
    by_control: dict[object, list[str]] = {}
    for control_id, check_id in maps:
        by_control.setdefault(control_id, []).append(check_id)
    return [
        ControlOut(
            ref=c.ref,
            title=c.title,
            description=c.description,
            checks=sorted(by_control.get(c.id, [])),
        )
        for c in controls
    ]


@router.get("/audit-log")
async def audit_log(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.AUDIT_READ))],
    action: Annotated[SafeText | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> Page[AuditOut]:
    base = select(AuditLog).where(AuditLog.tenant_id == tdb.principal.tenant_id)
    if action:
        base = base.where(AuditLog.action == action)
    async with tdb.transaction() as db:
        total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
        rows = (
            await db.execute(
                base.order_by(AuditLog.at.desc(), AuditLog.id.desc()).limit(limit).offset(offset)
            )
        ).scalars()
        return Page(
            items=[AuditOut.model_validate(r) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


@health.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Liveness: the process is up. Says nothing about dependencies."""
    return {"status": "ok"}


@health.get("/readyz", include_in_schema=False)
async def readyz(svc: ServicesDep) -> JSONResponse:
    """Readiness: the database answers and the schema is at this build's migration head."""
    try:
        async with svc.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            ready = await current_revision(conn) == head_revision()
    except Exception:
        ready = False
    return JSONResponse(
        {"status": "ready" if ready else "not_ready"}, status_code=200 if ready else 503
    )
