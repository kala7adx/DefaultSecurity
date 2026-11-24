"""Worker loops: job runners, lease heartbeats, the reaper, the sweeper and the scheduler
(ARCHITECTURE §11)."""

from __future__ import annotations

import asyncio
import os
import random
import socket
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any, Final
from uuid import UUID, uuid4

from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import IntegrityError

from skyline_core.db.models import Integration, IntegrationStatus, JobKind, ScanRun, ScanTrigger
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.logging import bind_correlation_id, clear_context, get_logger, new_correlation_id
from skyline_core.queue import (
    ClaimedJob,
    ReapedJob,
    ScanPayload,
    VerifyIntegrationPayload,
    sanitise_error,
)
from skyline_worker.context import PermanentJobError, WorkerContext
from skyline_worker.pipeline.evaluate import run_evaluate
from skyline_worker.pipeline.scan import LeaseLostError, fail_scan, run_scan
from skyline_worker.pipeline.verify import run_verify, verify_gave_up

_log = get_logger(__name__)

#: Advisory lock key for the scheduler leader ("skyline" in ASCII, as a bigint).
SCHEDULER_LOCK: Final = 0x736B796C696E65
#: A busy integration (scan already active) is retried this soon, not a full interval later.
BUSY_RETRY: Final = timedelta(minutes=15)
#: How far back the sweeper looks for dead jobs whose run or integration wasn't settled.
SWEEP_WINDOW: Final = timedelta(hours=1)
_HEARTBEAT_RETRY_SECONDS: Final = 5.0

Handler = Callable[[WorkerContext, ClaimedJob], Coroutine[Any, Any, None]]

HANDLERS: Final[Mapping[JobKind, Handler]] = {
    JobKind.SCAN: run_scan,
    JobKind.EVALUATE: run_evaluate,
    JobKind.VERIFY_INTEGRATION: run_verify,
}


def worker_id() -> str:
    return f"{socket.gethostname()[:40]}-{os.getpid()}-{uuid4().hex[:6]}"


class Worker:
    """Runs ``concurrency`` job loops plus the reaper, sweeper and scheduler until ``stop()``."""

    def __init__(
        self,
        ctx: WorkerContext,
        *,
        concurrency: int = 2,
        lease: timedelta = timedelta(minutes=5),
        poll_seconds: float = 2.0,
        scheduler_seconds: float = 60.0,
        reaper_seconds: float = 30.0,
        sweeper_seconds: float = 300.0,
        heartbeat_file: Path | None = None,
    ) -> None:
        self.ctx = ctx
        self.id = worker_id()
        self._concurrency = concurrency
        self._lease = lease
        self._poll = poll_seconds
        self._scheduler_seconds = scheduler_seconds
        self._reaper_seconds = reaper_seconds
        self._sweeper_seconds = sweeper_seconds
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

    async def run_once(self, worker_id: str | None = None) -> bool:
        """Claim and run one job. Returns False if the queue was empty.

        The handler runs as its own task. If the heartbeat finds the lease gone (the reaper
        gave the job to another worker), the handler is cancelled and nothing is committed;
        handlers also re-check ownership in their final transaction (:class:`LeaseLostError`).
        """
        wid = worker_id or self.id
        async with system_scope(self.ctx.session_factory) as session:
            job = await self.ctx.queue.claim(session, worker_id=wid, lease=self._lease)
        if job is None:
            return False
        bind_correlation_id(new_correlation_id())
        lost = asyncio.Event()
        handler = asyncio.create_task(HANDLERS[job.kind](self.ctx, job))
        heartbeat = asyncio.create_task(self._heartbeat(job, handler, lost))
        try:
            await handler
        except asyncio.CancelledError:
            current = asyncio.current_task()
            if not lost.is_set() or (current is not None and current.cancelling()):
                raise  # the worker is stopping
            _log.warning("job_lease_lost", job_id=str(job.id), kind=job.kind.value)
        except LeaseLostError:
            _log.warning("job_lease_lost", job_id=str(job.id), kind=job.kind.value)
        except Exception as exc:
            _log.exception("job_failed", job_id=str(job.id), kind=job.kind.value)
            await self._failed(job, exc)
        else:
            async with system_scope(self.ctx.session_factory) as session:
                await self.ctx.queue.complete(session, job_id=job.id, worker_id=wid)
        finally:
            heartbeat.cancel()
            clear_context()
        return True

    async def _failed(self, job: ClaimedJob, exc: Exception) -> None:
        async with system_scope(self.ctx.session_factory) as session:
            retried = await self.ctx.queue.fail(
                session,
                job=job,
                worker_id=job.worker_id,
                error=sanitise_error(exc),
                retryable=not isinstance(exc, PermanentJobError),
            )
        if not retried and not (
            isinstance(exc, PermanentJobError) and isinstance(job.payload, VerifyIntegrationPayload)
        ):
            # A permanently failed verify (our connector's fault) leaves the integration as it
            # is; the audit row and status detail explain it.
            await self._settle_dead(
                ReapedJob(job.id, job.tenant_id, job.kind, job.payload, dead=True),
                scan_reason="the scan failed unexpectedly",
            )

    async def _settle_dead(self, job: ReapedJob, *, scan_reason: str) -> None:
        """A job won't run again: close its scan run, or end its integration's "verifying"."""
        try:
            if isinstance(job.payload, ScanPayload):
                await fail_scan(self.ctx, job.tenant_id, job.payload.scan_run_id, scan_reason)
            elif isinstance(job.payload, VerifyIntegrationPayload):
                await verify_gave_up(
                    self.ctx, job.tenant_id, job.payload.integration_id, dead_job_id=job.id
                )
        except Exception:  # the sweeper tries again later
            _log.exception("settle_dead_job_failed", job_id=str(job.id))

    async def _heartbeat(
        self, job: ClaimedJob, handler: asyncio.Task[None], lost: asyncio.Event
    ) -> None:
        interval = self._lease.total_seconds() / 3
        delay = interval
        while not handler.done():
            await asyncio.sleep(delay)
            try:
                async with system_scope(self.ctx.session_factory) as session:
                    held = await self.ctx.queue.heartbeat(
                        session, job_id=job.id, worker_id=job.worker_id, lease=self._lease
                    )
            except Exception as exc:
                _log.warning("heartbeat_failed", job_id=str(job.id), error_type=type(exc).__name__)
                delay = min(interval, _HEARTBEAT_RETRY_SECONDS)
                continue
            delay = interval
            if not held:
                lost.set()
                handler.cancel()
                return

    async def _job_loop(self, worker_id: str) -> None:
        while not self._stopping.is_set():
            try:
                busy = await self.run_once(worker_id)
            except Exception:
                _log.exception("job_loop_error")
                busy = False
            if not busy:
                await self._sleep(self._poll * random.uniform(0.8, 1.2))  # noqa: S311 - jitter

    # ------------------------------------------------------------------ reaper and sweeper

    async def reap_once(self) -> list[ReapedJob]:
        async with system_scope(self.ctx.session_factory) as session:
            reaped = await self.ctx.queue.reap_expired(session)
        for job in reaped:
            if job.dead:
                await self._settle_dead(job, scan_reason="the scan timed out")
        return reaped

    async def sweep_once(self) -> int:
        """Settle recently dead jobs again, in case settling failed the first time. Each step
        is idempotent: it only touches runs still active and integrations still verifying."""
        async with system_scope(self.ctx.session_factory, read_only=True) as session:
            dead = await self.ctx.queue.recently_dead(
                session, kinds=(JobKind.SCAN, JobKind.VERIFY_INTEGRATION), window=SWEEP_WINDOW
            )
        for job in dead:
            await self._settle_dead(job, scan_reason="the scan failed unexpectedly")
        return len(dead)

    # ------------------------------------------------------------------ scheduler

    async def schedule_once(self) -> int:
        """If this worker wins the leader lock, enqueue scans for due integrations."""
        async with self.ctx.engine.connect() as conn:
            try:
                leader = bool(
                    (await conn.execute(select(func.pg_try_advisory_lock(SCHEDULER_LOCK)))).scalar()
                )
                await conn.commit()
            except BaseException:
                # We can't tell whether the session holds the lock: never pool it again.
                await conn.invalidate()
                raise
            if not leader:
                return 0
            try:
                return await self._schedule_due()
            finally:
                try:
                    await conn.execute(select(func.pg_advisory_unlock(SCHEDULER_LOCK)))
                    await conn.commit()
                except BaseException:
                    _log.exception("scheduler_unlock_failed")
                    await conn.invalidate()  # closing the session releases the lock

    async def _schedule_due(self) -> int:
        async with system_scope(self.ctx.session_factory) as session:
            due = (await session.execute(text("SELECT * FROM skyline.due_integrations(100)"))).all()
            await session.execute(text("SELECT skyline.purge_login_attempts()"))
        enqueued = 0
        for tenant_id, integration_id in due:
            try:
                enqueued += await self._enqueue_scheduled(tenant_id, integration_id)
            except Exception:  # one bad integration must not stop the rest
                _log.exception("schedule_failed", integration_id=str(integration_id))
        return enqueued

    async def _enqueue_scheduled(self, tenant_id: UUID, integration_id: UUID) -> int:
        """Queue one scheduled scan for a connected, live integration. ``next_scan_at`` moves
        on even when a scan is already active (by at most ``BUSY_RETRY``), so busy
        integrations can't keep the due list full and starve the others."""
        async with tenant_scope(self.ctx.session_factory, tenant_id) as session:
            live = (
                Integration.tenant_id == tenant_id,
                Integration.id == integration_id,
                Integration.status == IntegrationStatus.CONNECTED.value,
                Integration.deleted_at.is_(None),
            )
            interval = (
                await session.execute(
                    update(Integration)
                    .where(*live)
                    .values(next_scan_at=func.now() + Integration.scan_interval)
                    .returning(Integration.scan_interval)
                )
            ).scalar_one_or_none()
            if interval is None:
                return 0  # changed or deleted since the due list was read
            try:
                async with session.begin_nested():
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
            except IntegrityError as exc:
                if "uq_jobs_one_active_scan" not in str(exc):
                    raise
                await session.execute(
                    update(Integration)
                    .where(*live)
                    .values(next_scan_at=func.now() + min(interval, BUSY_RETRY))
                )
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
        # One lease-holder ID per loop, so ownership checks can tell the loops apart.
        tasks = [
            asyncio.create_task(self._job_loop(f"{self.id}/{n}")) for n in range(self._concurrency)
        ]
        tasks += [
            asyncio.create_task(self._periodic("reaper", self._reaper_seconds, self.reap_once)),
            asyncio.create_task(self._periodic("sweeper", self._sweeper_seconds, self.sweep_once)),
            asyncio.create_task(
                self._periodic("scheduler", self._scheduler_seconds, self.schedule_once)
            ),
            asyncio.create_task(self._alive()),
        ]
        await self._stopping.wait()
        await asyncio.gather(*tasks, return_exceptions=True)
        _log.info("worker_stopped", worker_id=self.id)
