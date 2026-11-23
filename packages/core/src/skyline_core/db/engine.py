"""Async engine and session factory. One engine per process, one transaction per unit of work."""

from __future__ import annotations

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from skyline_core.db.base import SCHEMA
from skyline_core.settings import CoreSettings, SettingsError


def database_url(settings: CoreSettings) -> URL:
    """Build the connection URL. ``URL`` escapes every part; never log it unmasked."""
    if settings.db_password is None:
        msg = "SKYLINE_DB_PASSWORD_FILE is required"
        raise SettingsError(msg)
    return URL.create(
        "postgresql+asyncpg",
        username=settings.db_user,
        password=settings.db_password.get_secret_value(),
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def create_engine(settings: CoreSettings, *, application_name: str) -> AsyncEngine:
    """Create the process-wide engine with defensive server-side timeouts."""
    return create_async_engine(
        database_url(settings),
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_pool_size,
        pool_pre_ping=True,
        pool_recycle=1800,
        # Never put bound values (hashes, tokens, verifiers) into exception text or logs.
        hide_parameters=True,
        connect_args={
            "ssl": settings.db_ssl(),
            "timeout": 10,
            "server_settings": {
                "application_name": application_name,
                "search_path": SCHEMA,
                "statement_timeout": str(settings.db_statement_timeout_ms),
                "lock_timeout": "10000",
                "idle_in_transaction_session_timeout": "60000",
            },
        },
    )


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Sessions that don't expire objects on commit (we return plain data, not ORM state)."""
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
