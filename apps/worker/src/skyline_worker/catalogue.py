"""Sync the shipped check and framework catalogues into the global tables (run by migrate).

A changed check definition must bump its ``version``: syncing the same version with a
different content hash fails, so edits can't silently change what a finding means.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_checks.loader import LoadedCheck
from skyline_core.db.models import Check, CheckControlMap, Control, Framework
from skyline_frameworks.loader import FrameworkBundle, check_integrity

#: Namespace for deterministic control IDs: uuid5(namespace, "<framework>:<ref>").
CONTROL_NAMESPACE: Final = uuid.UUID("6f6c7a5e-3c1b-4b8e-9a51-7d1a2b3c4d5e")


class CatalogueSyncError(RuntimeError):
    """The shipped catalogue conflicts with what is already in the database."""


@dataclass(frozen=True, slots=True)
class SyncReport:
    checks: int
    controls: int
    mappings: int
    unmapped: dict[str, list[str]]


def control_id(framework_id: str, ref: str) -> uuid.UUID:
    return uuid.uuid5(CONTROL_NAMESPACE, f"{framework_id}:{ref}")


async def _sync_checks(session: AsyncSession, checks: Sequence[LoadedCheck]) -> None:
    stored = {
        row.id: row
        for row in (
            await session.execute(select(Check.id, Check.version, Check.content_hash))
        ).all()
    }
    for check in checks:
        d = check.definition
        previous = stored.get(d.id)
        if previous is not None:
            if d.version < previous.version:
                msg = f"{d.id}: version {d.version} is older than the stored {previous.version}"
                raise CatalogueSyncError(msg)
            if d.version == previous.version and bytes(previous.content_hash) != check.content_hash:
                msg = f"{d.id}: definition changed without a version bump"
                raise CatalogueSyncError(msg)
        values = {
            "version": d.version,
            "provider": d.provider,
            "severity": d.severity.value,
            "title": d.title,
            "metadata": d.model_dump(mode="json"),  # column name (ORM attribute is "meta")
            "content_hash": check.content_hash,
            "enabled": True,
        }
        statement = insert(Check).values(id=d.id, **values)
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[Check.id], set_={**values, "updated_at": func.now()}
            )
        )
    # Checks no longer shipped are disabled, never deleted (findings reference them).
    shipped = [c.definition.id for c in checks]
    await session.execute(update(Check).where(Check.id.not_in(shipped)).values(enabled=False))


async def _sync_framework(session: AsyncSession, bundle: FrameworkBundle) -> tuple[int, int]:
    cat = bundle.catalogue
    framework_values = {
        "name": cat.name,
        "version": cat.version,
        "source_url": str(cat.source_url),
        "description": cat.description,
    }
    statement = insert(Framework).values(id=cat.id, **framework_values)
    await session.execute(
        statement.on_conflict_do_update(index_elements=[Framework.id], set_=framework_values)
    )
    for control in cat.controls:
        values = {"title": control.title, "description": control.description}
        statement = insert(Control).values(
            id=control_id(cat.id, control.ref), framework_id=cat.id, ref=control.ref, **values
        )
        await session.execute(
            statement.on_conflict_do_update(index_elements=[Control.id], set_=values)
        )
    wanted = {
        (check_id, control_id(cat.id, ref))
        for check_id, refs in bundle.mappings.items()
        for ref in refs
    }
    framework_controls = [control_id(cat.id, c.ref) for c in cat.controls]
    existing = set(
        (
            await session.execute(
                select(CheckControlMap.check_id, CheckControlMap.control_id).where(
                    CheckControlMap.control_id.in_(framework_controls)
                )
            )
        ).all()
    )
    for check_id, ctl in existing - wanted:
        await session.execute(
            delete(CheckControlMap).where(
                CheckControlMap.check_id == check_id, CheckControlMap.control_id == ctl
            )
        )
    for check_id, ctl in wanted - existing:  # new mappings always start unreviewed
        await session.execute(insert(CheckControlMap).values(check_id=check_id, control_id=ctl))
    return len(cat.controls), len(wanted)


async def catalogue_drift(session: AsyncSession, checks: Sequence[LoadedCheck]) -> list[str]:
    """Differences between this process's checks and the synced catalogue (empty = in sync).

    The worker refuses to start on drift: it would otherwise record findings under a check
    version whose stored definition (title, remediation, mappings) says something else.
    """
    stored = {
        row.id: (row.version, bytes(row.content_hash))
        for row in (
            await session.execute(
                select(Check.id, Check.version, Check.content_hash).where(Check.enabled)
            )
        ).all()
    }
    shipped = {c.definition.id: (c.definition.version, c.content_hash) for c in checks}
    problems = [f"{cid}: not synced (run skyline-migrate)" for cid in shipped if cid not in stored]
    problems += [
        f"{cid}: differs from the synced version"
        for cid, value in shipped.items()
        if cid in stored and stored[cid] != value
    ]
    problems += [f"{cid}: enabled but not shipped" for cid in stored if cid not in shipped]
    return sorted(problems)


async def sync_catalogue(
    session: AsyncSession, checks: Sequence[LoadedCheck], bundles: Sequence[FrameworkBundle]
) -> SyncReport:
    unmapped = check_integrity(bundles, [c.definition.id for c in checks])
    await _sync_checks(session, checks)
    controls = mappings = 0
    for bundle in bundles:
        c, m = await _sync_framework(session, bundle)
        controls += c
        mappings += m
    return SyncReport(checks=len(checks), controls=controls, mappings=mappings, unmapped=unmapped)
