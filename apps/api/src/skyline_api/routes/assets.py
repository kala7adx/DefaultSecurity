"""Asset inventory (graph nodes) and their relationships."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import aliased
from sqlalchemy.sql import ColumnElement

from skyline_api.auth import Principal, TenantDbDep, require
from skyline_api.errors import not_found
from skyline_api.rbac import Permission
from skyline_api.schemas import AssetDetailOut, AssetOut, Page, RelatedAssetOut, SafeText
from skyline_core.db.models import Asset, Finding, FindingStatus, Integration, Relationship

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _live_integration(tenant_id: UUID) -> ColumnElement[bool]:
    """Assets of a deleted integration (raw config included) are no longer shown."""
    live = select(Integration.id).where(
        Integration.tenant_id == tenant_id, Integration.deleted_at.is_(None)
    )
    return Asset.integration_id.in_(live)


@router.get("")
async def list_assets(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.ASSETS_READ))],
    integration_id: UUID | None = None,
    resource_type: Annotated[SafeText | None, Query(max_length=100)] = None,
    q: Annotated[SafeText | None, Query(max_length=100)] = None,
    include_deleted: bool = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> Page[AssetOut]:
    base = select(Asset).where(
        Asset.tenant_id == tdb.principal.tenant_id, _live_integration(tdb.principal.tenant_id)
    )
    if not include_deleted:
        base = base.where(Asset.deleted_at.is_(None))
    if integration_id is not None:
        base = base.where(Asset.integration_id == integration_id)
    if resource_type:
        base = base.where(Asset.resource_type == resource_type)
    if q:
        base = base.where(Asset.name.ilike(f"%{_escape_like(q)}%", escape="\\"))
    async with tdb.transaction() as db:
        total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
        rows = (
            await db.execute(
                base.order_by(Asset.resource_type, Asset.name).limit(limit).offset(offset)
            )
        ).scalars()
        return Page(
            items=[AssetOut.model_validate(r) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


@router.get("/{asset_id}")
async def get_asset(
    asset_id: UUID,
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.ASSETS_READ))],
) -> AssetDetailOut:
    tenant_id = tdb.principal.tenant_id
    other = aliased(Asset)
    async with tdb.transaction() as db:
        asset = (
            await db.execute(
                select(Asset).where(
                    Asset.tenant_id == tenant_id,
                    Asset.id == asset_id,
                    _live_integration(tenant_id),
                )
            )
        ).scalar_one_or_none()
        if asset is None:
            raise not_found("asset")
        related: list[RelatedAssetOut] = []
        for direction, own, far in (
            ("out", Relationship.src_asset_id, Relationship.dst_asset_id),
            ("in", Relationship.dst_asset_id, Relationship.src_asset_id),
        ):
            rows = await db.execute(
                select(Relationship.type, other.id, other.name, other.resource_type)
                .join(other, other.id == far)
                .where(
                    Relationship.tenant_id == tenant_id,
                    own == asset_id,
                    Relationship.deleted_at.is_(None),
                )
                .limit(200)
            )
            related += [
                RelatedAssetOut(
                    direction=direction,  # type: ignore[arg-type]
                    type=r.type,
                    asset_id=r.id,
                    name=r.name,
                    resource_type=r.resource_type,
                )
                for r in rows
            ]
        open_findings = (
            await db.execute(
                select(func.count()).where(
                    Finding.tenant_id == tenant_id,
                    Finding.asset_id == asset_id,
                    Finding.status == FindingStatus.OPEN.value,
                )
            )
        ).scalar_one()
        return AssetDetailOut(
            **AssetOut.model_validate(asset).model_dump(),
            raw_config=asset.raw_config,
            relationships=related,
            open_findings=open_findings,
        )
