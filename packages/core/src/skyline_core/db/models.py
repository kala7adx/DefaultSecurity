"""Database models (ARCHITECTURE §4).

Global tables have no ``tenant_id``. Every other table is tenant-owned: ``tenant_id NOT NULL``,
Row-Level Security in the migration, and **composite foreign keys** ``(tenant_id, x_id)`` so a
row can never reference another tenant's row, even by mistake.

The schema is created by Alembic migrations, not ``create_all``. A test compares these models
with the migrated database and fails on any drift.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Interval,
    Numeric,
    PrimaryKeyConstraint,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from skyline_core.db.base import Base


def _in(column: str, values: type[StrEnum]) -> str:
    joined = ", ".join(f"'{v.value}'" for v in values)
    return f"{column} IN ({joined})"


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class IntegrationStatus(StrEnum):
    PENDING_REGISTRATION = "pending_registration"
    VERIFYING = "verifying"
    CONNECTED = "connected"
    ACCESS_LOST = "access_lost"
    DISABLED = "disabled"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD = "dead"


class JobKind(StrEnum):
    SCAN = "scan"
    EVALUATE = "evaluate"
    VERIFY_INTEGRATION = "verify_integration"


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    ONBOARDING = "onboarding"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class FindingEventType(StrEnum):
    NEW = "new"
    STILL_OPEN = "still_open"
    AUTO_RESOLVED = "auto_resolved"
    REOPENED = "reopened"


class ExceptionScope(StrEnum):
    FINDING = "finding"
    CHECK = "check"
    ASSET = "asset"
    CHECK_ON_ASSET = "check_on_asset"


class ActorType(StrEnum):
    USER = "user"
    SYSTEM = "system"
    ANONYMOUS = "anonymous"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


_NOW = func.now()

# --------------------------------------------------------------------------- global tables


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint(r"slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name="slug_format"),
        CheckConstraint("length(name) BETWEEN 1 AND 200", name="name_length"),
        CheckConstraint("status IN ('active', 'suspended')", name="status"),
        ForeignKeyConstraint(
            ["id", "redaction_key_secret_id"],
            ["secrets.tenant_id", "secrets.id"],
            use_alter=True,
            name="fk_tenants_redaction_key_secrets",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'active'"))
    #: The tenant's redaction HMAC key in ``secrets``. Set once at tenant creation by the owner
    #: role; looked up by this ID, never by "newest", so no other role can substitute a key.
    redaction_key_secret_id: Mapped[UUID | None]
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email = lower(email) AND length(email) <= 320", name="email_normalised"),
        CheckConstraint("status IN ('active', 'disabled')", name="status"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    must_change_password: Mapped[bool] = mapped_column(server_default=text("false"))
    status: Mapped[str] = mapped_column(Text, server_default=text("'active'"))
    password_changed_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_login_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)


class LoginAttempt(Base):
    """Pre-authentication throttling records, keyed by an HMAC of the account or IP."""

    __tablename__ = "login_attempts"
    __table_args__ = (
        CheckConstraint("subject_type IN ('account', 'ip')", name="subject_type"),
        Index(None, "subject_type", "subject_hash", "at"),
        Index(None, "at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    subject_type: Mapped[str] = mapped_column(Text)
    subject_hash: Mapped[bytes]
    succeeded: Mapped[bool]
    at: Mapped[datetime] = mapped_column(server_default=_NOW)


class Check(Base):
    __tablename__ = "checks"
    __table_args__ = (CheckConstraint(_in("severity", Severity), name="severity"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    version: Mapped[int]
    provider: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict[str, Any]] = mapped_column("metadata")
    content_hash: Mapped[bytes]
    enabled: Mapped[bool] = mapped_column(server_default=text("true"))
    updated_at: Mapped[datetime] = mapped_column(server_default=_NOW)


class Framework(Base):
    __tablename__ = "frameworks"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, server_default=text("''"))


class Control(Base):
    __tablename__ = "controls"
    __table_args__ = (UniqueConstraint("framework_id", "ref"),)

    id: Mapped[UUID] = mapped_column(primary_key=True)
    framework_id: Mapped[str] = mapped_column(Text, ForeignKey("frameworks.id", ondelete="CASCADE"))
    ref: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)


class CheckControlMap(Base):
    __tablename__ = "check_control_map"
    __table_args__ = (PrimaryKeyConstraint("check_id", "control_id"),)

    check_id: Mapped[str] = mapped_column(Text, ForeignKey("checks.id", ondelete="CASCADE"))
    control_id: Mapped[UUID] = mapped_column(ForeignKey("controls.id", ondelete="CASCADE"))
    reviewed: Mapped[bool] = mapped_column(server_default=text("false"))
    reviewed_by: Mapped[str | None] = mapped_column(Text)
    reviewed_at: Mapped[datetime | None]


# --------------------------------------------------------------------------- tenant-owned


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        PrimaryKeyConstraint("tenant_id", "user_id"),
        CheckConstraint(_in("role", Role), name="role"),
    )

    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    role: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)


class Session(Base):
    """Opaque web sessions (ADR-0008). Only the SHA-256 of the token is stored."""

    __tablename__ = "sessions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["memberships.tenant_id", "memberships.user_id"],
            ondelete="CASCADE",
        ),
        CheckConstraint("length(token_hash) = 32", name="token_hash_length"),
        CheckConstraint("expires_at <= created_at + interval '12 hours'", name="max_lifetime"),
        Index(None, "user_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[UUID]
    token_hash: Mapped[bytes] = mapped_column(unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]


class Secret(Base):
    """Envelope-encrypted secrets (ADR-0006). The API role can insert but not read these."""

    __tablename__ = "secrets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        CheckConstraint(
            "purpose IN ('integration_credential', 'redaction_hmac_key')", name="purpose"
        ),
        CheckConstraint("length(nonce) = 12", name="nonce_length"),
        # The API may insert but not read key material, so never add an implicit RETURNING.
        {"implicit_returning": False},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    purpose: Mapped[str] = mapped_column(Text)
    key_provider: Mapped[str] = mapped_column(Text)
    key_id: Mapped[str] = mapped_column(Text)
    wrapped_dek: Mapped[bytes]
    nonce: Mapped[bytes]
    ciphertext: Mapped[bytes]
    format_version: Mapped[int] = mapped_column(server_default=text("1"))
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "credential_secret_id"], ["secrets.tenant_id", "secrets.id"]
        ),
        ForeignKeyConstraint(
            ["tenant_id", "created_by"], ["memberships.tenant_id", "memberships.user_id"]
        ),
        CheckConstraint(_in("status", IntegrationStatus), name="status"),
        CheckConstraint("length(name) BETWEEN 1 AND 200", name="name_length"),
        CheckConstraint(r"provider ~ '^[a-z][a-z0-9_]{1,31}$'", name="provider_format"),
        CheckConstraint(
            "scan_interval BETWEEN interval '1 hour' AND interval '7 days'", name="scan_interval"
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    provider: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    config: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    #: AWS confused-deputy defence (ADR-0011): 244 random bits from gen_random_uuid(),
    #: generated by PostgreSQL, unique across all tenants, not insertable by the API.
    external_id: Mapped[str] = mapped_column(
        Text,
        unique=True,
        server_default=text("replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '')"),
    )
    status: Mapped[str] = mapped_column(Text)
    status_detail: Mapped[str] = mapped_column(Text, server_default=text("''"))
    credential_secret_id: Mapped[UUID | None]
    scan_interval: Mapped[timedelta] = mapped_column(
        Interval, server_default=text("interval '24 hours'")
    )
    next_scan_at: Mapped[datetime | None]
    last_scan_at: Mapped[datetime | None]
    template_version: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[UUID | None]
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    updated_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    deleted_at: Mapped[datetime | None]


class Job(Base):
    """Postgres-backed job queue (ADR-0003). Payloads hold IDs only."""

    __tablename__ = "jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "integration_id"], ["integrations.tenant_id", "integrations.id"]
        ),
        CheckConstraint(_in("kind", JobKind), name="kind"),
        CheckConstraint(_in("status", JobStatus), name="status"),
        CheckConstraint("attempts >= 0 AND max_attempts BETWEEN 1 AND 20", name="attempts"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_object"),
        CheckConstraint(
            "integration_id::text IS NOT DISTINCT FROM payload->>'integration_id'",
            name="payload_integration",
        ),
        Index(
            "uq_jobs_one_active_scan",
            "integration_id",
            unique=True,
            postgresql_where=text("kind = 'scan' AND status IN ('queued', 'running')"),
        ),
        Index(
            "uq_jobs_one_queued_verify",
            "integration_id",
            unique=True,
            postgresql_where=text("kind = 'verify_integration' AND status = 'queued'"),
        ),
        Index("ix_jobs_claimable", "run_at", postgresql_where=text("status = 'queued'")),
        Index("ix_jobs_leases", "lease_expires_at", postgresql_where=text("status = 'running'")),
        {"implicit_returning": False},  # the API role has INSERT but no SELECT on jobs
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    kind: Mapped[str] = mapped_column(Text)
    integration_id: Mapped[UUID | None]
    payload: Mapped[dict[str, Any]]
    status: Mapped[str] = mapped_column(Text, server_default=text("'queued'"))
    run_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    attempts: Mapped[int] = mapped_column(server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(server_default=text("3"))
    lease_expires_at: Mapped[datetime | None]
    locked_by: Mapped[str | None] = mapped_column(Text)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    updated_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    finished_at: Mapped[datetime | None]


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        ForeignKeyConstraint(
            ["tenant_id", "integration_id"], ["integrations.tenant_id", "integrations.id"]
        ),
        ForeignKeyConstraint(
            ["tenant_id", "requested_by"], ["memberships.tenant_id", "memberships.user_id"]
        ),
        CheckConstraint(_in("trigger", ScanTrigger), name="trigger"),
        CheckConstraint(_in("status", ScanStatus), name="status"),
        Index(None, "tenant_id", "integration_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    integration_id: Mapped[UUID]
    trigger: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, server_default=text("'queued'"))
    requested_by: Mapped[UUID | None]
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    stats: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    scope_errors: Mapped[list[Any]] = mapped_column(server_default=text("'[]'::jsonb"))


class Asset(Base):
    """Graph nodes (ADR-0004). ``raw_config`` is redacted before it is stored."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("tenant_id", "integration_id", "native_id"),
        ForeignKeyConstraint(
            ["tenant_id", "integration_id"], ["integrations.tenant_id", "integrations.id"]
        ),
        ForeignKeyConstraint(
            ["tenant_id", "last_seen_scan_id"], ["scan_runs.tenant_id", "scan_runs.id"]
        ),
        Index(None, "tenant_id", "resource_type"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    integration_id: Mapped[UUID]
    provider: Mapped[str] = mapped_column(Text)
    resource_type: Mapped[str] = mapped_column(Text)
    native_id: Mapped[str] = mapped_column(String(2048))
    scope_id: Mapped[str] = mapped_column(Text)
    account_id: Mapped[str | None] = mapped_column(Text)
    region: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    raw_config: Mapped[dict[str, Any]]
    config_hash: Mapped[bytes]
    first_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_seen_scan_id: Mapped[UUID]
    deleted_at: Mapped[datetime | None]


class Relationship(Base):
    """Graph edges (ADR-0004)."""

    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "src_asset_id", "dst_asset_id", "type"),
        ForeignKeyConstraint(
            ["tenant_id", "integration_id"], ["integrations.tenant_id", "integrations.id"]
        ),
        ForeignKeyConstraint(["tenant_id", "src_asset_id"], ["assets.tenant_id", "assets.id"]),
        ForeignKeyConstraint(["tenant_id", "dst_asset_id"], ["assets.tenant_id", "assets.id"]),
        ForeignKeyConstraint(
            ["tenant_id", "last_seen_scan_id"], ["scan_runs.tenant_id", "scan_runs.id"]
        ),
        Index(None, "tenant_id", "dst_asset_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    integration_id: Mapped[UUID]
    src_asset_id: Mapped[UUID]
    dst_asset_id: Mapped[UUID]
    type: Mapped[str] = mapped_column(Text)
    properties: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    first_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_seen_scan_id: Mapped[UUID]
    deleted_at: Mapped[datetime | None]


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("tenant_id", "asset_id", "check_id"),
        ForeignKeyConstraint(
            ["tenant_id", "integration_id"], ["integrations.tenant_id", "integrations.id"]
        ),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["assets.tenant_id", "assets.id"]),
        ForeignKeyConstraint(
            ["tenant_id", "last_scan_run_id"], ["scan_runs.tenant_id", "scan_runs.id"]
        ),
        CheckConstraint(_in("status", FindingStatus), name="status"),
        CheckConstraint(_in("severity", Severity), name="severity"),
        CheckConstraint("reopened_count >= 0", name="reopened_count"),
        Index(None, "tenant_id", "status", "severity"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    integration_id: Mapped[UUID]
    asset_id: Mapped[UUID]
    check_id: Mapped[str] = mapped_column(Text, ForeignKey("checks.id"))
    status: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(6, 2))
    evidence: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    first_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    last_seen_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    resolved_at: Mapped[datetime | None]
    reopened_count: Mapped[int] = mapped_column(server_default=text("0"))
    last_scan_run_id: Mapped[UUID]


class FindingEvent(Base):
    __tablename__ = "finding_events"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "finding_id"], ["findings.tenant_id", "findings.id"]),
        ForeignKeyConstraint(["tenant_id", "scan_run_id"], ["scan_runs.tenant_id", "scan_runs.id"]),
        CheckConstraint(_in("event", FindingEventType), name="event"),
        Index(None, "tenant_id", "finding_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    finding_id: Mapped[UUID]
    scan_run_id: Mapped[UUID]
    event: Mapped[str] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(server_default=_NOW)


class FindingException(Base):
    """A mute. Whether a finding is muted is computed at query time, so expiry needs no job."""

    __tablename__ = "exceptions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "finding_id"], ["findings.tenant_id", "findings.id"]),
        ForeignKeyConstraint(["tenant_id", "asset_id"], ["assets.tenant_id", "assets.id"]),
        *(
            ForeignKeyConstraint(
                ["tenant_id", column], ["memberships.tenant_id", "memberships.user_id"]
            )
            for column in ("created_by", "approved_by", "revoked_by")
        ),
        CheckConstraint(_in("scope_type", ExceptionScope), name="scope_type"),
        CheckConstraint(
            "(scope_type = 'finding' AND finding_id IS NOT NULL"
            " AND check_id IS NULL AND asset_id IS NULL)"
            " OR (scope_type = 'check' AND check_id IS NOT NULL"
            " AND finding_id IS NULL AND asset_id IS NULL)"
            " OR (scope_type = 'asset' AND asset_id IS NOT NULL"
            " AND finding_id IS NULL AND check_id IS NULL)"
            " OR (scope_type = 'check_on_asset' AND check_id IS NOT NULL AND asset_id IS NOT NULL"
            " AND finding_id IS NULL)",
            name="scope_columns",
        ),
        CheckConstraint("length(justification) BETWEEN 10 AND 2000", name="justification"),
        CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '365 days'",
            name="expiry",
        ),
        Index(None, "tenant_id", "scope_type"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"))
    scope_type: Mapped[str] = mapped_column(Text)
    finding_id: Mapped[UUID | None]
    check_id: Mapped[str | None] = mapped_column(Text, ForeignKey("checks.id"))
    asset_id: Mapped[UUID | None]
    justification: Mapped[str] = mapped_column(Text)
    created_by: Mapped[UUID]
    approved_by: Mapped[UUID]
    created_at: Mapped[datetime] = mapped_column(server_default=_NOW)
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_by: Mapped[UUID | None]


class AuditLog(Base):
    """Append-only security audit trail. App roles get INSERT and SELECT only."""

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(_in("actor_type", ActorType), name="actor_type"),
        CheckConstraint(_in("outcome", AuditOutcome), name="outcome"),
        Index(None, "tenant_id", "at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    tenant_id: Mapped[UUID | None] = mapped_column(ForeignKey("tenants.id"))
    actor_type: Mapped[str] = mapped_column(Text)
    actor_id: Mapped[UUID | None]
    action: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(server_default=text("'{}'::jsonb"))
    ip: Mapped[IPv4Address | IPv6Address | None] = mapped_column(INET)
    correlation_id: Mapped[str | None] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(server_default=_NOW)


#: Tables that carry ``tenant_id`` and are protected by Row-Level Security.
TENANT_TABLES: tuple[str, ...] = (
    "memberships",
    "sessions",
    "secrets",
    "integrations",
    "jobs",
    "scan_runs",
    "assets",
    "relationships",
    "findings",
    "finding_events",
    "exceptions",
    "audit_log",
)
