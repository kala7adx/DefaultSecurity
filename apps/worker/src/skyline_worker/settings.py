"""Worker and migrate settings (environment variables prefixed ``SKYLINE_``)."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from pydantic import Field, SecretStr

from skyline_core.settings import CoreSettings


class WorkerSettings(CoreSettings):
    """Settings for ``skyline-worker`` (DB role ``skyline_worker``)."""

    db_user: str = "skyline_worker"
    worker_concurrency: int = Field(default=2, ge=1, le=32)
    lease_seconds: int = Field(default=300, ge=30, le=3600)
    poll_seconds: float = Field(default=2.0, ge=0.1, le=60)
    scheduler_seconds: float = Field(default=60.0, ge=5, le=3600)
    reaper_seconds: float = Field(default=30.0, ge=5, le=3600)
    sweeper_seconds: float = Field(default=300.0, ge=30, le=3600)
    # Evaluation between statements can be CPU-heavy on large tenants: allow longer gaps.
    db_idle_in_transaction_timeout_ms: int = Field(default=300_000, ge=1_000, le=3_600_000)
    heartbeat_file: Path | None = Path("/tmp/skyline-worker-heartbeat")  # noqa: S108 - tmpfs


class MigrateSettings(CoreSettings):
    """Settings for ``skyline-migrate`` (DB role ``skyline_owner``)."""

    secret_fields: ClassVar[frozenset[str]] = frozenset({"db_password", "bootstrap_admin_password"})

    db_user: str = "skyline_owner"
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: SecretStr | None = None
    bootstrap_tenant_slug: str = Field(default="default", pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    bootstrap_tenant_name: str = Field(default="Default", min_length=1, max_length=200)
