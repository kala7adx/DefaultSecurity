"""Catalogue sync and first-run bootstrap (what skyline-migrate does)."""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import func, select, text

from skyline_checks.loader import LoadedCheck
from skyline_core.crypto import SecretSealer, create_kek_file
from skyline_core.db.models import Check, CheckControlMap, Control, Tenant, User
from skyline_core.db.tenancy import system_scope
from skyline_core.security.passwords import verify_password
from skyline_core.settings import Environment
from skyline_frameworks.loader import load_frameworks
from skyline_worker.bootstrap import BootstrapError, bootstrap, normalise_email
from skyline_worker.catalogue import CatalogueSyncError, control_id, sync_catalogue
from skyline_worker.migrate import migrate
from skyline_worker.settings import MigrateSettings
from testsupport import Database, fresh_database

from .conftest import KEYS

pytestmark = pytest.mark.db


async def test_catalogue_is_synced_with_mappings(
    db: Database, catalogue: Sequence[LoadedCheck]
) -> None:
    async with system_scope(db.factory("skyline_api")) as session:
        checks = set((await session.execute(select(Check.id).where(Check.enabled))).scalars())
        controls = (await session.execute(select(func.count()).select_from(Control))).scalar()
        maps = (
            await session.execute(
                select(CheckControlMap.check_id, CheckControlMap.reviewed).where(
                    CheckControlMap.control_id == control_id("cyber-essentials-3.3", "CE.UAC")
                )
            )
        ).all()
    assert checks == {c.definition.id for c in catalogue}
    assert controls == 15
    assert [(m.check_id, m.reviewed) for m in maps] == [("fake.identity.admin_without_mfa", False)]


async def test_resync_is_idempotent(db: Database, catalogue: Sequence[LoadedCheck]) -> None:
    async with system_scope(db.factory("skyline_owner")) as session:
        report = await sync_catalogue(session, catalogue, load_frameworks())
    assert report.unmapped["cyber-essentials-3.3"] == ["fake.storage.bucket_encryption"]


async def test_edit_without_version_bump_is_rejected(
    db: Database, catalogue: Sequence[LoadedCheck]
) -> None:
    check = catalogue[0]
    edited = replace(check, content_hash=secrets.token_bytes(32))
    with pytest.raises(CatalogueSyncError, match="without a version bump"):
        async with system_scope(db.factory("skyline_owner")) as session:
            await sync_catalogue(session, [edited, *catalogue[1:]], load_frameworks())
    older = replace(check, definition=check.definition.model_copy(update={"version": 0}))
    with pytest.raises(CatalogueSyncError, match="older"):
        async with system_scope(db.factory("skyline_owner")) as session:
            await sync_catalogue(session, [older, *catalogue[1:]], load_frameworks())


@pytest.mark.parametrize(
    "email", ["not-an-email", "a@b", "x" * 400 + "@example.com", "a b@example.com"]
)
def test_bootstrap_email_validation(email: str) -> None:
    with pytest.raises(BootstrapError):
        normalise_email(email)


def test_bootstrap_email_is_normalised() -> None:
    assert normalise_email("  Admin@Example.COM ") == "admin@example.com"


async def test_bootstrap_backfills_missing_redaction_keys(db: Database) -> None:
    from testsupport import create_tenant

    tenant = await create_tenant(db)
    result = await bootstrap(
        db.factory("skyline_owner"),
        SecretSealer(KEYS),
        admin_email="admin@example.com",
        admin_password=None,
        tenant_slug="default",
        tenant_name="Default",
    )
    assert result.created is False
    assert result.redaction_keys_created >= 1
    async with system_scope(db.factory("skyline_owner")) as session:
        key = (
            await session.execute(
                select(Tenant.redaction_key_secret_id).where(Tenant.id == tenant.id)
            )
        ).scalar()
        await session.execute(text("SELECT 1"))
    assert key is not None


async def test_migrate_end_to_end_on_a_fresh_database(
    db: Database, postgres_container: Any, tmp_path: Path
) -> None:
    kek = tmp_path / "kek.json"
    create_kek_file(kek)
    password = secrets.token_urlsafe(18)
    async with fresh_database(
        db,
        name="skyline_migrate_e2e",
        superuser=postgres_container.username,
        superuser_password=postgres_container.password,
    ) as fresh:
        settings = MigrateSettings(
            env=Environment.TEST,
            db_host=fresh.host,
            db_port=fresh.port,
            db_name=fresh.name,
            db_user="skyline_owner",
            db_password=SecretStr(db.passwords["skyline_owner"]),
            db_sslmode="disable",
            local_kek_file=kek,
            bootstrap_admin_email="Admin@Example.com",
            bootstrap_admin_password=SecretStr(password),
        )
        await migrate(settings)
        await migrate(settings)  # idempotent
        async with system_scope(fresh.factory("skyline_owner")) as session:
            tenants = (await session.execute(select(Tenant))).scalars().all()
            users = (await session.execute(select(User))).scalars().all()
        assert [(t.slug, t.redaction_key_secret_id is not None) for t in tenants] == [
            ("default", True)
        ]
        assert [(u.email, u.must_change_password) for u in users] == [("admin@example.com", True)]
        async with system_scope(fresh.factory("skyline_api")) as session:
            rows = (
                await session.execute(
                    text("SELECT * FROM skyline.auth_lookup_user('admin@example.com')")
                )
            ).all()
        assert len(rows) == 1
        assert verify_password(rows[0].password_hash, password)


async def test_migrate_requires_a_bootstrap_password_on_first_run(
    db: Database, postgres_container: Any, tmp_path: Path
) -> None:
    kek = tmp_path / "kek.json"
    create_kek_file(kek)
    async with fresh_database(
        db,
        name="skyline_migrate_nopw",
        superuser=postgres_container.username,
        superuser_password=postgres_container.password,
    ) as fresh:
        settings = MigrateSettings(
            env=Environment.TEST,
            db_host=fresh.host,
            db_port=fresh.port,
            db_name=fresh.name,
            db_password=SecretStr(db.passwords["skyline_owner"]),
            db_sslmode="disable",
            local_kek_file=kek,
        )
        with pytest.raises(BootstrapError, match="BOOTSTRAP_ADMIN_PASSWORD_FILE"):
            await migrate(settings)
