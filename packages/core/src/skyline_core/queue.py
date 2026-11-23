"""Postgres-backed job queue behind an interface (ADR-0003, ARCHITECTURE §11).

* Payloads are JSON with **IDs only**, validated by a Pydantic model per job kind. No pickling.
* :meth:`PostgresJobQueue.claim` uses ``FOR UPDATE SKIP LOCKED`` so workers never contend.
* A claimed job holds a lease; :meth:`heartbeat` extends it and :meth:`reap_expired` returns
  jobs whose worker died to the queue (or marks them dead after ``max_attempts``).
* Enqueueing happens inside the caller's tenant transaction, atomically with related rows.
"""

from __future__ import annotations

import random
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import and_, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_core.db.models import Job, JobKind, JobStatus
from skyline_core.redaction import redact_for_log

_MAX_ERROR_CHARS: Final = 500
_BACKOFF_BASE_SECONDS: Final = 15
_BACKOFF_CAP_SECONDS: Final = 15 * 60


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScanPayload(_Payload):
    scan_run_id: UUID
    integration_id: UUID


class EvaluatePayload(_Payload):
    scan_run_id: UUID
    integration_id: UUID


class VerifyIntegrationPayload(_Payload):
    integration_id: UUID


PAYLOAD_MODELS: Final[Mapping[JobKind, type[_Payload]]] = {
    JobKind.SCAN: ScanPayload,
    JobKind.EVALUATE: EvaluatePayload,
    JobKind.VERIFY_INTEGRATION: VerifyIntegrationPayload,
}

type JobPayload = ScanPayload | EvaluatePayload | VerifyIntegrationPayload


class InvalidJobError(Exception):
    """A stored job can't be decoded; it is dead-lettered, never retried."""


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    id: UUID
    tenant_id: UUID
    kind: JobKind
    payload: _Payload
    attempts: int
    max_attempts: int


@dataclass(frozen=True, slots=True)
class ReapedJob:
    id: UUID
    tenant_id: UUID
    kind: JobKind | None
    payload: _Payload | None  # None if the stored payload failed validation
    dead: bool


def sanitise_error(exc: BaseException) -> str:
    """A short, redacted description of a failure that is safe to store and show."""
    text = f"{type(exc).__name__}: {exc}"
    return str(redact_for_log(text))[:_MAX_ERROR_CHARS]


def retry_delay(attempts: int) -> timedelta:
    """Exponential backoff with full jitter, capped at 15 minutes."""
    ceiling = min(_BACKOFF_CAP_SECONDS, _BACKOFF_BASE_SECONDS * 2 ** max(attempts - 1, 0))
    # Jitter for scheduling only; not security sensitive.
    return timedelta(seconds=random.uniform(ceiling / 2, ceiling))  # noqa: S311


def decode_payload(kind: str, payload: Mapping[str, object]) -> tuple[JobKind, _Payload]:
    """Validate a stored payload against its kind's model."""
    try:
        job_kind = JobKind(kind)
        return job_kind, PAYLOAD_MODELS[job_kind].model_validate(payload)
    except (ValueError, KeyError, ValidationError) as exc:
        msg = "job payload failed validation"
        raise InvalidJobError(msg) from exc


class JobQueue(Protocol):
    """Queue operations. Implementations must be safe with many concurrent workers."""

    async def enqueue(
        self,
        session: AsyncSession,
        *,
        tenant_id: UUID,
        payload: JobPayload,
        run_at: datetime | None = None,
        max_attempts: int = 3,
    ) -> UUID: ...

    async def claim(
        self, session: AsyncSession, *, worker_id: str, lease: timedelta
    ) -> ClaimedJob | None: ...

    async def heartbeat(
        self, session: AsyncSession, *, job_id: UUID, worker_id: str, lease: timedelta
    ) -> bool: ...

    async def complete(self, session: AsyncSession, *, job_id: UUID, worker_id: str) -> None: ...

    async def fail(
        self,
        session: AsyncSession,
        *,
        job: ClaimedJob,
        worker_id: str,
        error: str,
        retryable: bool,
    ) -> bool: ...

    async def reap_expired(self, session: AsyncSession) -> list[ReapedJob]: ...


def _kind_of(payload: JobPayload) -> JobKind:
    for kind, model in PAYLOAD_MODELS.items():
        if type(payload) is model:
            return kind
    msg = "unknown payload type"
    raise InvalidJobError(msg)


class PostgresJobQueue:
    """:class:`JobQueue` on the ``jobs`` table."""

    async def enqueue(
        self,
        session: AsyncSession,
        *,
        tenant_id: UUID,
        payload: JobPayload,
        run_at: datetime | None = None,
        max_attempts: int = 3,
    ) -> UUID:
        """Insert a job. ``integration_id`` (used by the one-active-scan index) is always
        taken from the payload, so the two can never disagree."""
        job_id = uuid4()
        values: dict[str, object] = {
            "id": job_id,
            "tenant_id": tenant_id,
            "kind": _kind_of(payload).value,
            "integration_id": payload.integration_id,
            "payload": payload.model_dump(mode="json"),
            "max_attempts": max_attempts,
        }
        if run_at is not None:
            values["run_at"] = run_at
        await session.execute(insert(Job).values(**values))
        return job_id

    async def claim(
        self, session: AsyncSession, *, worker_id: str, lease: timedelta
    ) -> ClaimedJob | None:
        next_job = (
            select(Job.id)
            .where(Job.status == JobStatus.QUEUED.value, Job.run_at <= func.now())
            .order_by(Job.run_at)
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        row = (
            await session.execute(
                update(Job)
                .where(Job.id == next_job)
                .values(
                    status=JobStatus.RUNNING.value,
                    attempts=Job.attempts + 1,
                    lease_expires_at=func.now() + lease,
                    locked_by=worker_id,
                    updated_at=func.now(),
                )
                .returning(
                    Job.id, Job.tenant_id, Job.kind, Job.payload, Job.attempts, Job.max_attempts
                )
            )
        ).one_or_none()
        if row is None:
            return None
        try:
            kind, payload = decode_payload(row.kind, row.payload)
        except InvalidJobError:
            await self._finish(session, row.id, worker_id, JobStatus.DEAD, "invalid payload")
            return None
        return ClaimedJob(
            id=row.id,
            tenant_id=row.tenant_id,
            kind=kind,
            payload=payload,
            attempts=row.attempts,
            max_attempts=row.max_attempts,
        )

    async def heartbeat(
        self, session: AsyncSession, *, job_id: UUID, worker_id: str, lease: timedelta
    ) -> bool:
        result = await session.execute(
            update(Job)
            .where(
                Job.id == job_id,
                Job.locked_by == worker_id,
                Job.status == JobStatus.RUNNING.value,
            )
            .values(lease_expires_at=func.now() + lease, updated_at=func.now())
            .returning(Job.id)
        )
        return result.one_or_none() is not None

    async def _finish(
        self,
        session: AsyncSession,
        job_id: UUID,
        worker_id: str,
        status: JobStatus,
        error: str | None,
    ) -> None:
        await session.execute(
            update(Job)
            .where(Job.id == job_id, Job.locked_by == worker_id)
            .values(
                status=status.value,
                last_error=error,
                lease_expires_at=None,
                finished_at=func.now(),
                updated_at=func.now(),
            )
        )

    async def complete(self, session: AsyncSession, *, job_id: UUID, worker_id: str) -> None:
        await self._finish(session, job_id, worker_id, JobStatus.SUCCEEDED, None)

    async def fail(
        self,
        session: AsyncSession,
        *,
        job: ClaimedJob,
        worker_id: str,
        error: str,
        retryable: bool,
    ) -> bool:
        """Record a failure. Returns True if the job will be retried.

        ``error`` is redacted here as well, whatever the caller already did.
        """
        error = str(redact_for_log(error))[:_MAX_ERROR_CHARS]
        if retryable and job.attempts < job.max_attempts:
            await session.execute(
                update(Job)
                .where(Job.id == job.id, Job.locked_by == worker_id)
                .values(
                    status=JobStatus.QUEUED.value,
                    run_at=func.now() + retry_delay(job.attempts),
                    last_error=error,
                    lease_expires_at=None,
                    locked_by=None,
                    updated_at=func.now(),
                )
            )
            return True
        status = JobStatus.DEAD if retryable else JobStatus.FAILED
        await self._finish(session, job.id, worker_id, status, error)
        return False

    async def reap_expired(self, session: AsyncSession) -> list[ReapedJob]:
        """Requeue (or dead-letter) running jobs whose lease has expired."""
        expired = (
            await session.execute(
                select(Job.id, Job.tenant_id, Job.kind, Job.payload, Job.attempts, Job.max_attempts)
                .where(
                    and_(
                        Job.status == JobStatus.RUNNING.value,
                        Job.lease_expires_at < func.now(),
                    )
                )
                .with_for_update(skip_locked=True)
                .limit(100)
            )
        ).all()
        reaped: list[ReapedJob] = []
        for row in expired:
            try:
                kind, payload = decode_payload(row.kind, row.payload)
            except InvalidJobError:
                kind, payload = None, None
            # An undecodable job is dead-lettered at once: never retried, never trusted.
            dead = payload is None or row.attempts >= row.max_attempts
            values: dict[str, object] = {
                "lease_expires_at": None,
                "locked_by": None,
                "last_error": "lease expired (worker stopped or timed out)",
                "updated_at": func.now(),
            }
            if dead:
                values |= {"status": JobStatus.DEAD.value, "finished_at": func.now()}
            else:
                values |= {
                    "status": JobStatus.QUEUED.value,
                    "run_at": func.now() + retry_delay(row.attempts),
                }
            await session.execute(update(Job).where(Job.id == row.id).values(**values))
            reaped.append(
                ReapedJob(id=row.id, tenant_id=row.tenant_id, kind=kind, payload=payload, dead=dead)
            )
        return reaped
