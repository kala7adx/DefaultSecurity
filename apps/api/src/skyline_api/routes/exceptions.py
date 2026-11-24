"""Exceptions (mutes): justification and an expiry of at most 365 days are mandatory."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_api.auth import Principal, TenantDbDep, require
from skyline_api.errors import ApiError, not_found
from skyline_api.rbac import Permission
from skyline_api.schemas import ExceptionCreate, ExceptionOut, Page
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import (
    ActorType,
    Asset,
    Check,
    ExceptionScope,
    Finding,
    FindingException,
)

router = APIRouter(prefix="/api/v1/exceptions", tags=["exceptions"])

_MAX_DAYS = 365

_REQUIRED = {
    ExceptionScope.FINDING: ("finding_id",),
    ExceptionScope.CHECK: ("check_id",),
    ExceptionScope.ASSET: ("asset_id",),
    ExceptionScope.CHECK_ON_ASSET: ("check_id", "asset_id"),
}


def _validate(body: ExceptionCreate) -> None:
    given = {f for f in ("finding_id", "check_id", "asset_id") if getattr(body, f) is not None}
    if given != set(_REQUIRED[body.scope_type]):
        raise ApiError(422, "invalid_scope", "The exception scope and its targets don't match")
    if body.expires_at.tzinfo is None:
        raise ApiError(422, "invalid_expiry", "The expiry must include a time zone")
    now = datetime.now(UTC)
    # A minute of slack so a client asking for exactly 365 days isn't rejected by clock skew.
    if not now < body.expires_at <= now + timedelta(days=_MAX_DAYS) - timedelta(minutes=1):
        raise ApiError(
            422, "invalid_expiry", "The expiry must be in the future and within 365 days"
        )


async def _targets_exist(db: AsyncSession, tenant_id: UUID, body: ExceptionCreate) -> None:
    if body.finding_id is not None:
        found = await db.execute(
            select(Finding.id).where(Finding.tenant_id == tenant_id, Finding.id == body.finding_id)
        )
        if found.first() is None:
            raise not_found("finding")
    if body.asset_id is not None:
        found = await db.execute(
            select(Asset.id).where(Asset.tenant_id == tenant_id, Asset.id == body.asset_id)
        )
        if found.first() is None:
            raise not_found("asset")
    if (
        body.check_id is not None
        and (await db.execute(select(Check.id).where(Check.id == body.check_id))).first() is None
    ):
        raise not_found("check")


@router.post("", status_code=201)
async def create_exception(
    body: ExceptionCreate,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.EXCEPTIONS_WRITE))],
) -> ExceptionOut:
    _validate(body)
    exception_id = uuid4()
    async with tdb.transaction() as db:
        await _targets_exist(db, principal.tenant_id, body)
        await db.execute(
            insert(FindingException).values(
                id=exception_id,
                tenant_id=principal.tenant_id,
                scope_type=body.scope_type.value,
                finding_id=body.finding_id,
                check_id=body.check_id,
                asset_id=body.asset_id,
                justification=body.justification,
                created_by=principal.user_id,
                # Phase 5 adds a separate approver workflow; until then the creator approves.
                approved_by=principal.user_id,
                expires_at=body.expires_at,
            )
        )
        await record_audit(
            db,
            action=AuditAction.EXCEPTION_CREATED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            target_type="exception",
            target_id=exception_id,
            details={
                "scope_type": body.scope_type.value,
                "finding_id": str(body.finding_id) if body.finding_id else None,
                "check_id": body.check_id,
                "asset_id": str(body.asset_id) if body.asset_id else None,
                "expires_at": body.expires_at.isoformat(),
            },
            ip=principal.ip,
        )
        row = (
            await db.execute(
                select(FindingException).where(
                    FindingException.tenant_id == principal.tenant_id,
                    FindingException.id == exception_id,
                )
            )
        ).scalar_one()
        return ExceptionOut.model_validate(row)


@router.get("")
async def list_exceptions(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.FINDINGS_READ))],
    active: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> Page[ExceptionOut]:
    base = select(FindingException).where(FindingException.tenant_id == tdb.principal.tenant_id)
    if active:
        base = base.where(
            FindingException.revoked_at.is_(None), FindingException.expires_at > func.now()
        )
    async with tdb.transaction() as db:
        total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
        rows = (
            await db.execute(
                base.order_by(FindingException.created_at.desc()).limit(limit).offset(offset)
            )
        ).scalars()
        return Page(
            items=[ExceptionOut.model_validate(r) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


@router.post("/{exception_id}/revoke")
async def revoke_exception(
    exception_id: UUID,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.EXCEPTIONS_WRITE))],
) -> ExceptionOut:
    async with tdb.transaction() as db:
        row = (
            await db.execute(
                select(FindingException).where(
                    FindingException.tenant_id == principal.tenant_id,
                    FindingException.id == exception_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise not_found("exception")
        if row.revoked_at is not None:
            raise ApiError(409, "already_revoked", "The exception is already revoked")
        await db.execute(
            update(FindingException)
            .where(
                FindingException.tenant_id == principal.tenant_id,
                FindingException.id == exception_id,
            )
            .values(revoked_at=func.now(), revoked_by=principal.user_id)
        )
        await record_audit(
            db,
            action=AuditAction.EXCEPTION_REVOKED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            target_type="exception",
            target_id=exception_id,
            ip=principal.ip,
        )
        refreshed = (
            await db.execute(
                select(FindingException).where(
                    FindingException.tenant_id == principal.tenant_id,
                    FindingException.id == exception_id,
                )
            )
        ).scalar_one()
        await db.refresh(refreshed)
        return ExceptionOut.model_validate(refreshed)
