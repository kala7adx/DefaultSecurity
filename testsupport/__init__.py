"""Test support shared by every test package (fixtures live in the root ``conftest.py``).

One PostgreSQL 17 container per test session (same image digest as Compose), with the same
four roles as production, migrated by the real migration code. Tests connect as the role they
exercise (``skyline_api`` / ``skyline_worker``), so Row-Level Security and grants are real.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from uuid import UUID, uuid4

from pydantic import SecretStr
from sqlalchemy import insert, text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from skyline_core.db.engine import create_engine, create_session_factory
from skyline_core.db.migrate import upgrade_to_head
from skyline_core.db.models import Membership, Role, Tenant, User
from skyline_core.db.roles import LOGIN_ROLES, create_roles
from skyline_core.db.tenancy import tenant_scope
from skyline_core.security.passwords import hash_password
from skyline_core.settings import CoreSettings, Environment
from skyline_core.types import Sensitive

# Keep in sync with deploy/compose/docker-compose.yml.
POSTGRES_IMAGE = (
    "postgres:17-bookworm@sha256:837bed18782820fe967067cb5328b02b0d9992c1be9a37ee0c9c492cfc03af3b"
)


@dataclass
class Database:
    """Connection details and per-role engines for the test database."""

    host: str
    port: int
    passwords: dict[str, str]
    name: str = "skyline"
    engines: dict[str, AsyncEngine] = field(default_factory=dict)

    def settings(self, role: str) -> CoreSettings:
        return CoreSettings(
            env=Environment.TEST,
            db_host=self.host,
            db_port=self.port,
            db_name=self.name,
            db_user=role,
            db_password=SecretStr(self.passwords[role]),
            db_sslmode="disable",
        )

    def engine(self, role: str) -> AsyncEngine:
        if role not in self.engines:
            self.engines[role] = create_engine(self.settings(role), application_name=f"test-{role}")
        return self.engines[role]

    def factory(self, role: str) -> async_sessionmaker[AsyncSession]:
        return create_session_factory(self.engine(role))

    async def dispose(self) -> None:
        for engine in self.engines.values():
            await engine.dispose()


async def prepare_database(
    *, host: str, port: int, superuser: str, superuser_password: str
) -> Database:
    """Create roles and the database as a superuser, then migrate as the owner."""
    passwords = {role: secrets.token_hex(16) for role in LOGIN_ROLES}
    admin = create_async_engine(
        URL.create(
            "postgresql+asyncpg",
            username=superuser,
            password=superuser_password,
            host=host,
            port=port,
            database="postgres",
        ),
        hide_parameters=True,
    )
    async with admin.begin() as conn:
        await create_roles(conn, {r: Sensitive(p) for r, p in passwords.items()})
    async with admin.connect() as conn:
        autocommit = await conn.execution_options(isolation_level="AUTOCOMMIT")
        await autocommit.execute(text("CREATE DATABASE skyline OWNER skyline_owner"))
    await admin.dispose()
    database = Database(host=host, port=port, passwords=passwords)
    await upgrade_to_head(database.engine("skyline_owner"))
    return database


@dataclass(frozen=True)
class TenantFixture:
    id: UUID
    slug: str
    admin_id: UUID
    admin_email: str


async def create_tenant(
    db: Database, *, role: Role = Role.ADMIN, password: str | None = None
) -> TenantFixture:
    """Create a tenant with one member (via the owner role, as bootstrap would)."""
    tenant_id, user_id = uuid4(), uuid4()
    slug = f"t-{tenant_id.hex[:12]}"
    email = f"user-{user_id.hex[:12]}@example.com"
    owner = db.factory("skyline_owner")
    async with owner() as session, session.begin():
        await session.execute(insert(Tenant).values(id=tenant_id, slug=slug, name=slug))
        await session.execute(
            insert(User).values(
                id=user_id,
                email=email,
                password_hash=hash_password(password or secrets.token_urlsafe(18)),
            )
        )
    async with tenant_scope(owner, tenant_id) as session:
        await session.execute(
            insert(Membership).values(tenant_id=tenant_id, user_id=user_id, role=role.value)
        )
    return TenantFixture(id=tenant_id, slug=slug, admin_id=user_id, admin_email=email)


@asynccontextmanager
async def fresh_database(
    db: Database, *, name: str, superuser: str, superuser_password: str
) -> AsyncIterator[Database]:
    """An empty database owned by skyline_owner, dropped afterwards (same roles as ``db``)."""
    admin = create_async_engine(
        URL.create(
            "postgresql+asyncpg",
            username=superuser,
            password=superuser_password,
            host=db.host,
            port=db.port,
            database="postgres",
        ),
        isolation_level="AUTOCOMMIT",
        hide_parameters=True,
    )
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}" OWNER skyline_owner'))
    fresh = Database(host=db.host, port=db.port, passwords=db.passwords, name=name)
    try:
        yield fresh
    finally:
        await fresh.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        await admin.dispose()
