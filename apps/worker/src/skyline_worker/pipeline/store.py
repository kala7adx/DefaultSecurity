"""Persist collected assets and relationships (graph nodes and edges, ADR-0004).

Upserts are idempotent on ``(tenant_id, integration_id, native_id)``, so a retried scan is safe.
Only scopes that succeeded can mark their unseen assets deleted; a failed scope's data is
left exactly as it was (ARCHITECTURE §3).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_connectors.runner import CollectedAsset, ScopeResult
from skyline_core.db.models import Asset, Relationship

_BATCH = 500


@dataclass(slots=True)
class StoreStats:
    assets_seen: int = 0
    assets_deleted: int = 0
    relationships_seen: int = 0
    relationships_skipped: int = 0
    relationships_deleted: int = 0
    records_rejected: int = 0


def _chunks[T](items: Sequence[T], size: int = _BATCH) -> Iterable[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


async def _upsert_assets(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    integration_id: UUID,
    scan_run_id: UUID,
    provider: str,
    assets: Sequence[CollectedAsset],
) -> None:
    for chunk in _chunks(assets):
        statement = insert(Asset).values(
            [
                {
                    "id": uuid4(),
                    "tenant_id": tenant_id,
                    "integration_id": integration_id,
                    "provider": provider,
                    "resource_type": a.resource_type,
                    "native_id": a.native_id,
                    "scope_id": a.scope_id,
                    "account_id": a.account_id,
                    "region": a.region,
                    "name": a.name,
                    "tags": a.tags,
                    "raw_config": a.raw_config,
                    "config_hash": a.config_hash,
                    "last_seen_scan_id": scan_run_id,
                }
                for a in chunk
            ]
        )
        excluded = statement.excluded
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[Asset.tenant_id, Asset.integration_id, Asset.native_id],
                set_={
                    "resource_type": excluded.resource_type,
                    "scope_id": excluded.scope_id,
                    "account_id": excluded.account_id,
                    "region": excluded.region,
                    "name": excluded.name,
                    "tags": excluded.tags,
                    "raw_config": excluded.raw_config,
                    "config_hash": excluded.config_hash,
                    "last_seen_at": func.now(),
                    "last_seen_scan_id": excluded.last_seen_scan_id,
                    "deleted_at": None,
                },
            )
        )


async def _asset_ids(
    session: AsyncSession, *, tenant_id: UUID, integration_id: UUID
) -> dict[str, UUID]:
    rows = await session.execute(
        select(Asset.native_id, Asset.id).where(
            Asset.tenant_id == tenant_id,
            Asset.integration_id == integration_id,
            Asset.deleted_at.is_(None),
        )
    )
    return {row.native_id: row.id for row in rows.all()}


async def store_results(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    integration_id: UUID,
    scan_run_id: UUID,
    provider: str,
    results: Sequence[ScopeResult],
) -> StoreStats:
    """Write one scan's results in the caller's tenant transaction."""
    stats = StoreStats(records_rejected=sum(r.rejected for r in results))
    ok = [r for r in results if r.ok]
    ok_scopes = [r.scope.id for r in ok]
    assets = [a for r in ok for a in r.assets]
    stats.assets_seen = len(assets)
    await _upsert_assets(
        session,
        tenant_id=tenant_id,
        integration_id=integration_id,
        scan_run_id=scan_run_id,
        provider=provider,
        assets=assets,
    )

    if ok_scopes:
        deleted = await session.execute(
            update(Asset)
            .where(
                Asset.tenant_id == tenant_id,
                Asset.integration_id == integration_id,
                Asset.scope_id.in_(ok_scopes),
                Asset.last_seen_scan_id != scan_run_id,
                Asset.deleted_at.is_(None),
            )
            .values(deleted_at=func.now())
            .returning(Asset.id)
        )
        stats.assets_deleted = len(deleted.all())

    ids = await _asset_ids(session, tenant_id=tenant_id, integration_id=integration_id)
    edges: dict[tuple[UUID, UUID, str], dict[str, object]] = {}
    for rel in (rel for r in ok for rel in r.relationships):
        src, dst = ids.get(rel.src_native_id), ids.get(rel.dst_native_id)
        if src is None or dst is None:
            stats.relationships_skipped += 1
            continue
        edges[(src, dst, rel.type)] = {
            "id": uuid4(),
            "tenant_id": tenant_id,
            "integration_id": integration_id,
            "src_asset_id": src,
            "dst_asset_id": dst,
            "type": rel.type,
            "properties": rel.properties,
            "last_seen_scan_id": scan_run_id,
        }
    stats.relationships_seen = len(edges)
    for chunk in _chunks(list(edges.values())):
        statement = insert(Relationship).values(list(chunk))
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[
                    Relationship.tenant_id,
                    Relationship.src_asset_id,
                    Relationship.dst_asset_id,
                    Relationship.type,
                ],
                set_={
                    "properties": statement.excluded.properties,
                    "last_seen_at": func.now(),
                    "last_seen_scan_id": statement.excluded.last_seen_scan_id,
                    "deleted_at": None,
                },
            )
        )
    stats.relationships_deleted = await _retire_relationships(
        session,
        tenant_id=tenant_id,
        integration_id=integration_id,
        scan_run_id=scan_run_id,
        ok_scopes=ok_scopes,
    )
    return stats


async def _retire_relationships(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    integration_id: UUID,
    scan_run_id: UUID,
    ok_scopes: Sequence[str],
) -> int:
    """Edges belong to the scope of their source asset. Retire unseen ones in successful scopes,
    and any edge whose endpoint no longer exists."""
    ok_sources = select(Asset.id).where(
        Asset.tenant_id == tenant_id,
        Asset.integration_id == integration_id,
        Asset.scope_id.in_(ok_scopes),
    )
    gone = select(Asset.id).where(
        Asset.tenant_id == tenant_id,
        Asset.integration_id == integration_id,
        Asset.deleted_at.is_not(None),
    )
    result = await session.execute(
        update(Relationship)
        .where(
            Relationship.tenant_id == tenant_id,
            Relationship.integration_id == integration_id,
            Relationship.deleted_at.is_(None),
            or_(
                and_(
                    Relationship.last_seen_scan_id != scan_run_id,
                    Relationship.src_asset_id.in_(ok_sources),
                ),
                Relationship.src_asset_id.in_(gone),
                Relationship.dst_asset_id.in_(gone),
            ),
        )
        .values(deleted_at=func.now())
        .returning(Relationship.id)
    )
    return len(result.all())
