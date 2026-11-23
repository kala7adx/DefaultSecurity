"""Worker loops: job runners, lease heartbeats, the reaper and the scheduler (ARCHITECTURE §11)."""

from __future__ import annotations

import asyncio
import os
import random
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Final
from uuid import UUID, uuid4

from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import IntegrityError

from skyline_core.db.models import Integration, JobKind, ScanRun, ScanTrigger
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.logging import bind_correlation_id, clear_context, get_logger, new_correlation_id
from skyline_core.queue import ClaimedJob, ReapedJob, ScanPayload, sanitise_error
from skyline_worker.context import WorkerContext
from skyline_worker.pipeline.evaluate import run_evaluate
from skyline_worker.pipeline.scan import fail_scan, run_scan
from skyline_worker.pipeline.verify import run_verify

_log = get_logger(__name__)

#: Advisory lock key for the scheduler leader ("skyline" in ASCII, as a bigint).
SCHEDULER_LOCK: Final = 0x736B796C696E65

Handler = Callable[[WorkerContext, ClaimedJob], Awaitable[None]]

HANDLERS: Final[Mapping[JobKind, Handler]] = {
    JobKind.SCAN: run_scan,
    JobKind.EVALUATE: run_evaluate,
    JobKind.VERIFY_INTEGRATION: run_verify,
}


def worker_id() -> str:
    return f"{socket.gethostname()[:40]}-{os.getpid()}-{uuid4().hex[:6]}"


class Worker:
    """Runs ``concurrency`` job loops plus the reaper and scheduler until ``stop()``."""

    def __init__(
        self,
        ctx: WorkerContext,
        *,
        concurrency: int = 2,
        lease: timedelta = timedelta(minutes=5),
        poll_seconds: float = 2.0,
        scheduler_seconds: float = 60.0,
        reaper_seconds: float = 30.0,
        heartbeat_file: Path | None = None,
    ) -> None:
        self.ctx = ctx
        self.id = worker_id()
        self._concurrency = concurrency
        self._lease = lease
        self._poll = poll_seconds
        self._scheduler_seconds = scheduler_seconds
        self._reaper_seconds = reaper_seconds
        self._heartbeat_file = heartbeat_file
        self._stopping = asyncio.Event()

    def stop(self) -> None:
        self._stopping.set()

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)
        except TimeoutError:
            return

    # ------------------------------------------------------------------ jobs

    async def run_once(self) -> bool:
        """Claim and run one job. Returns False if the queue was empty."""
        async with system_scope(self.ctx.session_factory) as session:
            job = await self.ctx.queue.claim(session, worker_id=self.id, lease=self._lease)
        if job is None:
            return False
        bind_correlation_id(new_correlation_id())
        heartbeat = asyncio.create_task(self._heartbeat(job.id))
        try:
            await HANDLERS[job.kind](self.ctx, job)
        except Exception as exc:
            _log.exception("job_failed", job_id=str(job.id), kind=job.kind.value)
            await self._failed(job, exc)
        else:
            async with system_scope(self.ctx.session_factory) as session:
                await self.ctx.queue.complete(session, job_id=job.id, worker_id=self.id)
        finally:
            heartbeat.cancel()
            clear_context()
        return True

    async def _failed(self, job: ClaimedJob, exc: Exception) -> None:
        async with system_scope(self.ctx.session_factory) as session:
            retried = await self.ctx.queue.fail(
                session, job=job, worker_id=self.id, error=sanitise_error(exc), retryable=True
            )
        if not retried and isinstance(job.payload, ScanPayload):
            await fail_scan(
                self.ctx, job.tenant_id, job.payload.scan_run_id, "the scan failed unexpectedly"
            )

    async def _heartbeat(self, job_id: UUID) -> None:
        while True:
            await asyncio.sleep(self._lease.total_seconds() / 3)
            async with system_scope(self.ctx.session_factory) as session:
                if not await self.ctx.queue.heartbeat(
                    session, job_id=job_id, worker_id=self.id, lease=self._lease
                ):
                    return

    async def _job_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                busy = await self.run_once()
            except Exception:
                _log.exception("job_loop_error")
                busy = False
            if not busy:
                await self._sleep(self._poll * random.uniform(0.8, 1.2))  # noqa: S311 - jitter

    # ------------------------------------------------------------------ reaper

    async def reap_once(self) -> list[ReapedJob]:
        async with system_scope(self.ctx.session_factory) as session:
            reaped = await self.ctx.queue.reap_expired(session)
        for job in reaped:
            if job.dead and isinstance(job.payload, ScanPayload):
                await fail_scan(
                    self.ctx, job.tenant_id, job.payload.scan_run_id, "the scan timed out"
                )
        return reaped

    # ------------------------------------------------------------------ scheduler

    async def schedule_once(self) -> int:
        """If this worker wins the leader lock, enqueue scans for due integrations."""
        enqueued = 0
        async with self.ctx.engine.connect() as conn:
            leader = (
                await conn.execute(select(func.pg_try_advisory_lock(SCHEDULER_LOCK)))
            ).scalar()
            await conn.commit()
            if not leader:
                return 0
            try:
                async with system_scope(self.ctx.session_factory) as session:
                    due = (
                        await session.execute(text("SELECT * FROM skyline.due_integrations(100)"))
                    ).all()
                    await session.execute(text("SELECT skyline.purge_login_attempts()"))
                for tenant_id, integration_id in due:
                    enqueued += await self._enqueue_scheduled(tenant_id, integration_id)
            finally:
                await conn.execute(select(func.pg_advisory_unlock(SCHEDULER_LOCK)))
                await conn.commit()
        return enqueued

    async def _enqueue_scheduled(self, tenant_id: UUID, integration_id: UUID) -> int:
        try:
            async with tenant_scope(self.ctx.session_factory, tenant_id) as session:
                interval = (
                    await session.execute(
                        select(Integration.scan_interval).where(Integration.id == integration_id)
                    )
                ).scalar_one()
                await session.execute(
                    update(Integration)
                    .where(Integration.id == integration_id)
                    .values(next_scan_at=func.now() + interval)
                )
                scan_run_id = uuid4()
                await session.execute(
                    insert(ScanRun).values(
                        id=scan_run_id,
                        tenant_id=tenant_id,
                        integration_id=integration_id,
                        trigger=ScanTrigger.SCHEDULED.value,
                    )
                )
                await self.ctx.queue.enqueue(
                    session,
                    tenant_id=tenant_id,
                    payload=ScanPayload(scan_run_id=scan_run_id, integration_id=integration_id),
                )
        except IntegrityError:
            return 0  # a scan is already queued or running for this integration
        return 1

    # ------------------------------------------------------------------ main

    async def _periodic(
        self, name: str, seconds: float, fn: Callable[[], Awaitable[object]]
    ) -> None:
        while not self._stopping.is_set():
            try:
                await fn()
            except Exception:
                _log.exception("periodic_task_failed", task=name)
            await self._sleep(seconds)

    async def _alive(self) -> None:
        while not self._stopping.is_set() and self._heartbeat_file is not None:
            self._heartbeat_file.write_text(str(int(time.time())), encoding="ascii")
            await self._sleep(10)

    async def run(self) -> None:
        _log.info("worker_started", worker_id=self.id, concurrency=self._concurrency)
        tasks = [asyncio.create_task(self._job_loop()) for _ in range(self._concurrency)]
        tasks += [
            asyncio.create_task(self._periodic("reaper", self._reaper_seconds, self.reap_once)),
            asyncio.create_task(
                self._periodic("scheduler", self._scheduler_seconds, self.schedule_once)
            ),
            asyncio.create_task(self._alive()),
        ]
        await self._stopping.wait()
        await asyncio.gather(*tasks, return_exceptions=True)
        _log.info("worker_stopped", worker_id=self.id)
