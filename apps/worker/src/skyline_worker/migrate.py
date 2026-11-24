"""``skyline-migrate``: apply migrations, sync catalogues, bootstrap. Runs as ``skyline_owner``.

The whole run holds a session advisory lock, so two migrate runs started together (a Compose
restart, a Helm hook retry, two replicas) apply everything one after the other, never
interleaved.
"""

from __future__ import annotations

import asyncio
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine

from skyline_checks.loader import load_checks
from skyline_core.audit import AuditAction, record_audit
from skyline_core.crypto import LocalKeyProvider, SecretSealer
from skyline_core.db.engine import create_engine, create_session_factory
from skyline_core.db.migrate import upgrade_to_head
from skyline_core.db.models import ActorType
from skyline_core.db.tenancy import system_scope
from skyline_core.logging import configure_logging, get_logger
from skyline_core.settings import SettingsError
from skyline_frameworks.loader import load_frameworks
from skyline_worker.bootstrap import bootstrap
from skyline_worker.catalogue import sync_catalogue
from skyline_worker.settings import MigrateSettings

_log = get_logger("skyline.migrate")

#: Advisory lock key for migrate ("skymigr" in ASCII, as a bigint).
MIGRATE_LOCK: Final = 0x736B796D696772
LOCK_WAIT_SECONDS: Final = 600.0


class MigrateLockTimeoutError(RuntimeError):
    """Another migrate run held the lock for too long."""


@asynccontextmanager
async def migrate_lock(
    engine: AsyncEngine, *, wait_seconds: float = LOCK_WAIT_SECONDS
) -> AsyncIterator[None]:
    """Hold the migrate lock on a dedicated connection. Polls with ``pg_try_advisory_lock``
    so the wait isn't cut short by ``statement_timeout``."""
    async with engine.connect() as conn:
        deadline = time.monotonic() + wait_seconds
        while not (await conn.execute(select(func.pg_try_advisory_lock(MIGRATE_LOCK)))).scalar():
            await conn.commit()
            if time.monotonic() > deadline:
                raise MigrateLockTimeoutError("another skyline-migrate is still running")
            _log.info("waiting_for_migrate_lock")
            await asyncio.sleep(2)
        await conn.commit()
        try:
            yield
        finally:
            try:
                await conn.execute(select(func.pg_advisory_unlock(MIGRATE_LOCK)))
                await conn.commit()
            except Exception:
                await conn.invalidate()  # closing the connection releases the lock
                raise


async def migrate(settings: MigrateSettings) -> None:
    if settings.local_kek_file is None:
        msg = "SKYLINE_LOCAL_KEK_FILE is required"
        raise SettingsError(msg)
    sealer = SecretSealer(LocalKeyProvider.from_file(settings.local_kek_file))
    engine = create_engine(settings, application_name="skyline-migrate")
    try:
        async with migrate_lock(engine):
            await _migrate_locked(engine, settings, sealer)
    finally:
        await engine.dispose()


async def _migrate_locked(
    engine: AsyncEngine, settings: MigrateSettings, sealer: SecretSealer
) -> None:
    await upgrade_to_head(engine)
    factory = create_session_factory(engine)
    async with system_scope(factory) as session:
        report = await sync_catalogue(session, load_checks(), load_frameworks())
        await record_audit(
            session,
            action=AuditAction.CATALOGUE_SYNCED,
            tenant_id=None,
            actor_type=ActorType.SYSTEM,
            details={"checks": report.checks, "controls": report.controls},
        )
    _log.info(
        "catalogue_synced",
        checks=report.checks,
        controls=report.controls,
        mappings=report.mappings,
        unmapped=report.unmapped,
    )
    password = settings.bootstrap_admin_password
    result = await bootstrap(
        factory,
        sealer,
        admin_email=settings.bootstrap_admin_email,
        admin_password=password.get_secret_value() if password else None,
        tenant_slug=settings.bootstrap_tenant_slug,
        tenant_name=settings.bootstrap_tenant_name,
    )
    _log.info("bootstrap_done", created=result.created, keys=result.redaction_keys_created)


def main() -> None:
    settings = MigrateSettings()
    configure_logging(settings.log_level)
    try:
        asyncio.run(migrate(settings))
    except Exception:
        _log.exception("migrate_failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
