"""Everything a job handler needs, injected so tests can swap any part."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from skyline_checks.loader import LoadedCheck
from skyline_connectors.gateway import GatewayLimits
from skyline_connectors.runner import RunnerLimits
from skyline_core.crypto import SecretOpener
from skyline_core.queue import JobQueue


class PermanentJobError(RuntimeError):
    """A job failure that retrying can't fix (e.g. a read-only violation)."""


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class WorkerContext:
    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    opener: SecretOpener
    queue: JobQueue
    checks: Sequence[LoadedCheck]
    clock: Callable[[], datetime] = utcnow
    gateway_limits: GatewayLimits = field(default_factory=GatewayLimits)
    runner_limits: RunnerLimits = field(default_factory=RunnerLimits)
    #: Whether demo-only providers (``fake``) may run (development, or explicitly enabled).
    demo_providers_allowed: bool = False
