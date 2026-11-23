"""Migrations apply, roll back to base and apply again on a fresh database."""

from __future__ import annotations

import pytest
from alembic import command
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import create_async_engine
from testcontainers.community.postgres import PostgresContainer

from skyline_core.db.migrate import alembic_config, current_revision, head_revision, upgrade_to_head
from testsupport import Database

pytestmark = pytest.mark.db


async def test_upgrade_downgrade_upgrade(
    db: Database, postgres_container: PostgresContainer
) -> None:
    admin = create_async_engine(
        URL.create(
            "postgresql+asyncpg",
            username=postgres_container.username,
            password=postgres_container.password,
            host=db.host,
            port=db.port,
            database="postgres",
        ),
        isolation_level="AUTOCOMMIT",
    )
    async with admin.connect() as conn:
        await conn.execute(text("CREATE DATABASE skyline_roundtrip OWNER skyline_owner"))
    owner = create_async_engine(
        URL.create(
            "postgresql+asyncpg",
            username="skyline_owner",
            password=db.passwords["skyline_owner"],
            host=db.host,
            port=db.port,
            database="skyline_roundtrip",
        )
    )
    try:
        await upgrade_to_head(owner)
        async with owner.connect() as conn:
            await conn.run_sync(lambda sync: command.downgrade(alembic_config(sync), "base"))
            await conn.commit()
            assert await current_revision(conn) is None
        await upgrade_to_head(owner)
        async with owner.connect() as conn:
            assert await current_revision(conn) == head_revision()
    finally:
        await owner.dispose()
        async with admin.connect() as conn:
            await conn.execute(text("DROP DATABASE skyline_roundtrip WITH (FORCE)"))
        await admin.dispose()
