"""``skyline-worker``: run the job loops, reaper and scheduler until SIGTERM."""

from __future__ import annotations

import asyncio
import contextlib
import signal
from datetime import timedelta

from skyline_checks.loader import load_checks
from skyline_core.crypto import LocalKeyProvider, SecretOpener
from skyline_core.db.engine import create_engine, create_session_factory
from skyline_core.logging import configure_logging, get_logger
from skyline_core.queue import PostgresJobQueue
from skyline_core.settings import SettingsError
from skyline_worker.context import WorkerContext
from skyline_worker.runner import Worker
from skyline_worker.settings import WorkerSettings

_log = get_logger("skyline.worker")


async def serve(settings: WorkerSettings) -> None:
    if settings.local_kek_file is None:
        msg = "SKYLINE_LOCAL_KEK_FILE is required"
        raise SettingsError(msg)
    engine = create_engine(settings, application_name="skyline-worker")
    ctx = WorkerContext(
        engine=engine,
        session_factory=create_session_factory(engine),
        # Decrypt-only side of envelope encryption (ADR-0006).
        opener=SecretOpener(LocalKeyProvider.from_file(settings.local_kek_file)),
        queue=PostgresJobQueue(),
        checks=load_checks(),
    )
    worker = Worker(
        ctx,
        concurrency=settings.worker_concurrency,
        lease=timedelta(seconds=settings.lease_seconds),
        poll_seconds=settings.poll_seconds,
        scheduler_seconds=settings.scheduler_seconds,
        reaper_seconds=settings.reaper_seconds,
        heartbeat_file=settings.heartbeat_file,
    )
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError, AttributeError):  # Windows
            loop.add_signal_handler(sig, worker.stop)
    try:
        await worker.run()
    finally:
        await engine.dispose()


def main() -> None:
    settings = WorkerSettings()
    configure_logging(settings.log_level)
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve(settings))


if __name__ == "__main__":
    main()
