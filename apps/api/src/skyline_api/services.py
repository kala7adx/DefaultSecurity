"""Process-wide services, built once at start-up (or injected by tests)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from skyline_api.settings import ApiSettings
from skyline_core.crypto import LocalKeyProvider, SecretSealer
from skyline_core.db.engine import create_engine, create_session_factory
from skyline_core.queue import JobQueue, PostgresJobQueue
from skyline_core.settings import SettingsError
from skyline_core.types import Sensitive

_MIN_SESSION_KEY_BYTES = 32


@dataclass(frozen=True, slots=True)
class Services:
    settings: ApiSettings
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    #: Encrypt-only side of envelope encryption (ADR-0006): the API can't decrypt.
    sealer: SecretSealer
    queue: JobQueue
    session_key: Sensitive[bytes]
    #: Caps concurrent argon2 work (CPU and 64 MiB each) so a login flood can't exhaust the
    #: process; callers that find it full get 503 instead of queueing.
    hash_slots: asyncio.Semaphore = field(default_factory=lambda: asyncio.Semaphore(8))
    #: Hashes in flight per IP bucket (single process; the limit is a setting).
    hashing_by_ip: dict[str, int] = field(default_factory=dict)


def build_services(settings: ApiSettings) -> Services:
    if settings.session_key is None:
        msg = "SKYLINE_SESSION_KEY_FILE is required"
        raise SettingsError(msg)
    key = settings.session_key.get_secret_value().encode()
    if len(key) < _MIN_SESSION_KEY_BYTES:
        msg = "the session key must be at least 32 bytes"
        raise SettingsError(msg)
    if settings.local_kek_file is None:
        msg = "SKYLINE_LOCAL_KEK_FILE is required"
        raise SettingsError(msg)
    engine = create_engine(settings, application_name="skyline-api")
    return Services(
        settings=settings,
        engine=engine,
        session_factory=create_session_factory(engine),
        sealer=SecretSealer(LocalKeyProvider.from_file(settings.local_kek_file)),
        queue=PostgresJobQueue(),
        session_key=Sensitive(key),
        hash_slots=asyncio.Semaphore(settings.max_concurrent_hashes),
    )
