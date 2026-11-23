"""Programmatic Alembic: upgrade to head and report whether the schema is current."""

from __future__ import annotations

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from skyline_core.db.base import SCHEMA

SCRIPT_LOCATION = "skyline_core.db:migrations"


def alembic_config(connection: Connection | None = None) -> Config:
    """An in-memory Alembic config; no ``alembic.ini`` and no URL with a password in it."""
    config = Config()
    config.set_main_option("script_location", SCRIPT_LOCATION)
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def head_revision() -> str | None:
    """The newest revision shipped with this build."""
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


async def upgrade_to_head(engine: AsyncEngine) -> None:
    """Create the schema if needed and apply all migrations (run as ``skyline_owner``)."""
    async with engine.begin() as conn:
        await conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
    async with engine.connect() as conn:
        await conn.run_sync(lambda sync: command.upgrade(alembic_config(sync), "head"))
        await conn.commit()


async def current_revision(conn: AsyncConnection) -> str | None:
    """The revision recorded in the database, or ``None`` if not migrated."""

    def _read(sync: Connection) -> str | None:
        context = MigrationContext.configure(sync, opts={"version_table_schema": SCHEMA})
        return context.get_current_revision()

    return await conn.run_sync(_read)
