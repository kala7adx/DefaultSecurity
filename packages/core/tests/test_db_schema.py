"""The migrated database matches the models, and its security settings are what ADR-0007 says."""

from __future__ import annotations

from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.engine import Connection

from skyline_core.db.base import SCHEMA, Base
from skyline_core.db.migrate import current_revision, head_revision
from skyline_core.db.models import TENANT_TABLES
from testsupport import Database

pytestmark = pytest.mark.db


def _include_name(name: str | None, type_: str, _parent: object) -> bool:
    return name == SCHEMA if type_ == "schema" else True


async def test_models_match_migrations(db: Database) -> None:
    def _diff(conn: Connection) -> list[Any]:
        context = MigrationContext.configure(
            conn,
            opts={
                "include_schemas": True,
                "include_name": _include_name,
                "version_table_schema": SCHEMA,
                "compare_type": True,
            },
        )
        return list(compare_metadata(context, Base.metadata))

    async with db.engine("skyline_owner").connect() as conn:
        assert await conn.run_sync(_diff) == []


async def test_database_is_at_head(db: Database) -> None:
    async with db.engine("skyline_api").connect() as conn:
        assert await current_revision(conn) == head_revision()


async def test_every_tenant_table_has_forced_rls_and_tenant_id(db: Database) -> None:
    async with db.engine("skyline_owner").connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity"
                    " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                    " WHERE n.nspname = 'skyline' AND c.relkind = 'r'"
                )
            )
        ).all()
        tenant_columns = {
            r.table_name
            for r in await conn.execute(
                text(
                    "SELECT table_name FROM information_schema.columns"
                    " WHERE table_schema = 'skyline' AND column_name = 'tenant_id'"
                )
            )
        }
    flags = {r.relname: (r.relrowsecurity, r.relforcerowsecurity) for r in rows}
    for table in (*TENANT_TABLES, "users", "tenants"):
        assert flags[table] == (True, True), table
    # Every table with a tenant_id is protected (catches a new table without RLS).
    assert tenant_columns <= set(TENANT_TABLES)


async def test_app_roles_are_unprivileged(db: Database) -> None:
    async with db.engine("skyline_owner").connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb,"
                    " rolcanlogin FROM pg_roles WHERE rolname LIKE 'skyline_%'"
                )
            )
        ).all()
    roles = {r.rolname: r for r in rows}
    assert set(roles) == {"skyline_owner", "skyline_api", "skyline_worker", "skyline_definer"}
    for role in roles.values():
        assert not (role.rolsuper or role.rolbypassrls or role.rolcreaterole or role.rolcreatedb)
    assert not roles["skyline_definer"].rolcanlogin


async def test_definer_functions_are_pinned_and_not_public(db: Database) -> None:
    async with db.engine("skyline_owner").connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT p.proname, p.prosecdef, p.proconfig,"
                    " pg_get_userbyid(p.proowner) AS owner,"
                    " has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec"
                    " FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
                    " WHERE n.nspname = 'skyline'"
                )
            )
        ).all()
    assert rows
    for row in rows:
        assert not row.public_exec, row.proname
        if row.prosecdef:
            assert row.owner == "skyline_definer", row.proname
            assert row.proconfig == ["search_path=pg_catalog, skyline, pg_temp"], row.proname
    assert {r.proname for r in rows if r.prosecdef} == {
        "auth_lookup_user",
        "resolve_session",
        "change_password",
        "record_login_attempt",
        "recent_login_failures",
        "purge_login_attempts",
        "due_integrations",
    }
