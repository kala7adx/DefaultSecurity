"""``skyline-migrate``: apply migrations, sync catalogues, bootstrap. Runs as ``skyline_owner``."""

from __future__ import annotations

import asyncio
import sys

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


async def migrate(settings: MigrateSettings) -> None:
    if settings.local_kek_file is None:
        msg = "SKYLINE_LOCAL_KEK_FILE is required"
        raise SettingsError(msg)
    engine = create_engine(settings, application_name="skyline-migrate")
    try:
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
        sealer = SecretSealer(LocalKeyProvider.from_file(settings.local_kek_file))
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
    finally:
        await engine.dispose()


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
