"""Scans: trigger a scan, list scan runs."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, insert, select
from sqlalchemy.exc import IntegrityError

from skyline_api.auth import Principal, ServicesDep, TenantDbDep, require
from skyline_api.errors import ApiError, not_found
from skyline_api.rbac import Permission
from skyline_api.schemas import Page, ScanCreate, ScanOut
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import ActorType, Integration, IntegrationStatus, ScanRun, ScanTrigger
from skyline_core.queue import ScanPayload

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post("", status_code=202)
async def start_scan(
    body: ScanCreate,
    svc: ServicesDep,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.SCANS_RUN))],
) -> ScanOut:
    scan_run_id = uuid4()
    try:
        async with tdb.transaction() as db:
            status = (
                await db.execute(
                    select(Integration.status).where(
                        Integration.tenant_id == principal.tenant_id,
                        Integration.id == body.integration_id,
                        Integration.deleted_at.is_(None),
                    )
                )
            ).scalar_one_or_none()
            if status is None:
                raise not_found("integration")
            if status != IntegrationStatus.CONNECTED.value:
                raise ApiError(409, "not_connected", "The integration is not connected yet")
            await db.execute(
                insert(ScanRun).values(
                    id=scan_run_id,
                    tenant_id=principal.tenant_id,
                    integration_id=body.integration_id,
                    trigger=ScanTrigger.MANUAL.value,
                    requested_by=principal.user_id,
                )
            )
            await svc.queue.enqueue(
                db,
                tenant_id=principal.tenant_id,
                payload=ScanPayload(scan_run_id=scan_run_id, integration_id=body.integration_id),
            )
            await record_audit(
                db,
                action=AuditAction.SCAN_REQUESTED,
                tenant_id=principal.tenant_id,
                actor_type=ActorType.USER,
                actor_id=principal.user_id,
                target_type="integration",
                target_id=body.integration_id,
                ip=principal.ip,
            )
    except IntegrityError:
        raise ApiError(409, "scan_in_progress", "A scan is already queued or running") from None
    async with tdb.transaction() as db:
        row = (
            await db.execute(
                select(ScanRun).where(
                    ScanRun.tenant_id == principal.tenant_id, ScanRun.id == scan_run_id
                )
            )
        ).scalar_one()
        return ScanOut.model_validate(row)


@router.get("")
async def list_scans(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_READ))],
    integration_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> Page[ScanOut]:
    base = select(ScanRun).where(ScanRun.tenant_id == tdb.principal.tenant_id)
    if integration_id is not None:
        base = base.where(ScanRun.integration_id == integration_id)
    async with tdb.transaction() as db:
        total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
        rows = (
            await db.execute(base.order_by(ScanRun.created_at.desc()).limit(limit).offset(offset))
        ).scalars()
        return Page(
            items=[ScanOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
        )


@router.get("/{scan_run_id}")
async def get_scan(
    scan_run_id: UUID,
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_READ))],
) -> ScanOut:
    async with tdb.transaction() as db:
        row = (
            await db.execute(
                select(ScanRun).where(
                    ScanRun.tenant_id == tdb.principal.tenant_id, ScanRun.id == scan_run_id
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise not_found("scan")
        return ScanOut.model_validate(row)
