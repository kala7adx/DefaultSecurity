"""Tenant context for Row-Level Security (ADR-0007, ARCHITECTURE §8).

Every unit of work runs in one transaction. :func:`tenant_scope` sets ``app.tenant_id`` with
``set_config(..., is_local => true)`` as a bound parameter, so the setting ends with the
transaction and a pooled connection can never carry it into another request. Without it the
RLS policies compare against NULL and return no rows (fail closed).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

TENANT_SETTING = "app.tenant_id"


async def set_tenant(session: AsyncSession, tenant_id: UUID) -> None:
    """Bind the current transaction to ``tenant_id``."""
    await session.execute(select(func.set_config(TENANT_SETTING, str(tenant_id), True)))


async def _begin_read_only(session: AsyncSession) -> None:
    # Must be the first statement of the transaction. Static SQL, no input.
    await session.execute(text("SET TRANSACTION READ ONLY"))


@asynccontextmanager
async def tenant_scope(
    factory: async_sessionmaker[AsyncSession], tenant_id: UUID, *, read_only: bool = False
) -> AsyncIterator[AsyncSession]:
    """One transaction bound to one tenant. Commits on success, rolls back on error.

    ``read_only=True`` makes PostgreSQL reject any write, which is how GET/HEAD requests are
    guaranteed never to change state (ADR-0008).
    """
    async with factory() as session, session.begin():
        if read_only:
            await _begin_read_only(session)
        await set_tenant(session, tenant_id)
        yield session


@asynccontextmanager
async def system_scope(
    factory: async_sessionmaker[AsyncSession], *, read_only: bool = False
) -> AsyncIterator[AsyncSession]:
    """One transaction with **no** tenant: only global tables and SECURITY DEFINER lookups."""
    async with factory() as session, session.begin():
        if read_only:
            await _begin_read_only(session)
        yield session
