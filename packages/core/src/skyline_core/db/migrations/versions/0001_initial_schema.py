"""Initial schema: global and tenant-owned tables (generated from the models, then reviewed).

Row-Level Security, grants and SECURITY DEFINER functions are in 0002.

Revision ID: 0001
Revises: (none)
Create Date: 2026-11-23 22:36:06.797970
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "checks",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("content_hash", postgresql.BYTEA(), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name=op.f("ck_checks_severity"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_checks")),
        schema="skyline",
    )
    op.create_table(
        "frameworks",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_frameworks")),
        schema="skyline",
    )
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("subject_type", sa.Text(), nullable=False),
        sa.Column("subject_hash", postgresql.BYTEA(), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False),
        sa.Column(
            "at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "subject_type IN ('account', 'ip')", name=op.f("ck_login_attempts_subject_type")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_login_attempts")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_login_attempts_at"), "login_attempts", ["at"], unique=False, schema="skyline"
    )
    op.create_index(
        op.f("ix_login_attempts_subject_type_subject_hash_at"),
        "login_attempts",
        ["subject_type", "subject_hash", "at"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "tenants",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'active'"), nullable=False),
        sa.Column("redaction_key_secret_id", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'", name=op.f("ck_tenants_slug_format")
        ),
        sa.CheckConstraint("status IN ('active', 'suspended')", name=op.f("ck_tenants_status")),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 200", name=op.f("ck_tenants_name_length")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("slug", name=op.f("uq_tenants_slug")),
        schema="skyline",
    )
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column(
            "must_change_password", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("status", sa.Text(), server_default=sa.text("'active'"), nullable=False),
        sa.Column(
            "password_changed_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_login_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("status IN ('active', 'disabled')", name=op.f("ck_users_status")),
        sa.CheckConstraint(
            "email = lower(email) AND length(email) <= 320", name=op.f("ck_users_email_normalised")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
        schema="skyline",
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("actor_type", sa.Text(), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("correlation_id", sa.Text(), nullable=True),
        sa.Column(
            "at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "actor_type IN ('user', 'system', 'anonymous')", name=op.f("ck_audit_log_actor_type")
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')", name=op.f("ck_audit_log_outcome")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_audit_log_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_audit_log_tenant_id_at"),
        "audit_log",
        ["tenant_id", "at"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "controls",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("framework_id", sa.Text(), nullable=False),
        sa.Column("ref", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["framework_id"],
            ["skyline.frameworks.id"],
            name=op.f("fk_controls_framework_id_frameworks"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_controls")),
        sa.UniqueConstraint("framework_id", "ref", name=op.f("uq_controls_framework_id_ref")),
        schema="skyline",
    )
    op.create_table(
        "memberships",
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('admin', 'analyst', 'viewer')", name=op.f("ck_memberships_role")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_memberships_tenant_id_tenants")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["skyline.users.id"], name=op.f("fk_memberships_user_id_users")
        ),
        sa.PrimaryKeyConstraint("tenant_id", "user_id", name=op.f("pk_memberships")),
        schema="skyline",
    )
    op.create_table(
        "secrets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("key_provider", sa.Text(), nullable=False),
        sa.Column("key_id", sa.Text(), nullable=False),
        sa.Column("wrapped_dek", postgresql.BYTEA(), nullable=False),
        sa.Column("nonce", postgresql.BYTEA(), nullable=False),
        sa.Column("ciphertext", postgresql.BYTEA(), nullable=False),
        sa.Column("format_version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "purpose IN ('integration_credential', 'redaction_hmac_key')",
            name=op.f("ck_secrets_purpose"),
        ),
        sa.CheckConstraint("length(nonce) = 12", name=op.f("ck_secrets_nonce_length")),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_secrets_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_secrets")),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_secrets_tenant_id_id")),
        schema="skyline",
    )
    op.create_table(
        "check_control_map",
        sa.Column("check_id", sa.Text(), nullable=False),
        sa.Column("control_id", sa.UUID(), nullable=False),
        sa.Column("reviewed", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("reviewed_by", sa.Text(), nullable=True),
        sa.Column("reviewed_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["check_id"],
            ["skyline.checks.id"],
            name=op.f("fk_check_control_map_check_id_checks"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["skyline.controls.id"],
            name=op.f("fk_check_control_map_control_id_controls"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("check_id", "control_id", name=op.f("pk_check_control_map")),
        schema="skyline",
    )
    op.create_table(
        "integrations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "config",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "external_id",
            sa.Text(),
            server_default=sa.text(
                "replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '')"
            ),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("status_detail", sa.Text(), server_default=sa.text("''"), nullable=False),
        sa.Column("credential_secret_id", sa.UUID(), nullable=True),
        sa.Column(
            "scan_interval",
            sa.Interval(),
            server_default=sa.text("interval '24 hours'"),
            nullable=False,
        ),
        sa.Column("next_scan_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_scan_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("template_version", sa.Text(), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "provider ~ '^[a-z][a-z0-9_]{1,31}$'", name=op.f("ck_integrations_provider_format")
        ),
        sa.CheckConstraint(
            "scan_interval BETWEEN interval '1 hour' AND interval '7 days'",
            name=op.f("ck_integrations_scan_interval"),
        ),
        sa.CheckConstraint(
            "status IN ('pending_registration', 'verifying', 'connected', 'access_lost', 'disabled')",
            name=op.f("ck_integrations_status"),
        ),
        sa.CheckConstraint(
            "length(name) BETWEEN 1 AND 200", name=op.f("ck_integrations_name_length")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            ["skyline.memberships.tenant_id", "skyline.memberships.user_id"],
            name=op.f("fk_integrations_tenant_id_created_by_memberships"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "credential_secret_id"],
            ["skyline.secrets.tenant_id", "skyline.secrets.id"],
            name=op.f("fk_integrations_tenant_id_credential_secret_id_secrets"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_integrations_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integrations")),
        sa.UniqueConstraint("external_id", name=op.f("uq_integrations_external_id")),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_integrations_tenant_id_id")),
        schema="skyline",
    )
    op.create_table(
        "sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", postgresql.BYTEA(), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "expires_at <= created_at + interval '12 hours'", name=op.f("ck_sessions_max_lifetime")
        ),
        sa.CheckConstraint("length(token_hash) = 32", name=op.f("ck_sessions_token_hash_length")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["skyline.memberships.tenant_id", "skyline.memberships.user_id"],
            name=op.f("fk_sessions_tenant_id_user_id_memberships"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_sessions_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_sessions_token_hash")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_sessions_user_id"), "sessions", ["user_id"], unique=False, schema="skyline"
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'queued'"), nullable=False),
        sa.Column(
            "run_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default=sa.text("3"), nullable=False),
        sa.Column("lease_expires_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("locked_by", sa.Text(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "integration_id::text IS NOT DISTINCT FROM payload->>'integration_id'",
            name=op.f("ck_jobs_payload_integration"),
        ),
        sa.CheckConstraint("jsonb_typeof(payload) = 'object'", name=op.f("ck_jobs_payload_object")),
        sa.CheckConstraint(
            "kind IN ('scan', 'evaluate', 'verify_integration')", name=op.f("ck_jobs_kind")
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed', 'dead')",
            name=op.f("ck_jobs_status"),
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND max_attempts BETWEEN 1 AND 20", name=op.f("ck_jobs_attempts")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_id"],
            ["skyline.integrations.tenant_id", "skyline.integrations.id"],
            name=op.f("fk_jobs_tenant_id_integration_id_integrations"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_jobs_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
        schema="skyline",
    )
    op.create_index(
        "ix_jobs_claimable",
        "jobs",
        ["run_at"],
        unique=False,
        schema="skyline",
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_index(
        "ix_jobs_leases",
        "jobs",
        ["lease_expires_at"],
        unique=False,
        schema="skyline",
        postgresql_where=sa.text("status = 'running'"),
    )
    op.create_index(
        "uq_jobs_one_active_scan",
        "jobs",
        ["integration_id"],
        unique=True,
        schema="skyline",
        postgresql_where=sa.text("kind = 'scan' AND status IN ('queued', 'running')"),
    )
    op.create_index(
        "uq_jobs_one_queued_verify",
        "jobs",
        ["integration_id"],
        unique=True,
        schema="skyline",
        postgresql_where=sa.text("kind = 'verify_integration' AND status = 'queued'"),
    )
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("trigger", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'queued'"), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("started_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("finished_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "stats",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "scope_errors",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'partial', 'failed')",
            name=op.f("ck_scan_runs_status"),
        ),
        sa.CheckConstraint(
            "trigger IN ('manual', 'scheduled', 'onboarding')", name=op.f("ck_scan_runs_trigger")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_id"],
            ["skyline.integrations.tenant_id", "skyline.integrations.id"],
            name=op.f("fk_scan_runs_tenant_id_integration_id_integrations"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "requested_by"],
            ["skyline.memberships.tenant_id", "skyline.memberships.user_id"],
            name=op.f("fk_scan_runs_tenant_id_requested_by_memberships"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_scan_runs_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_runs")),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_scan_runs_tenant_id_id")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_scan_runs_tenant_id_integration_id_created_at"),
        "scan_runs",
        ["tenant_id", "integration_id", "created_at"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("resource_type", sa.Text(), nullable=False),
        sa.Column("native_id", sa.String(length=2048), nullable=False),
        sa.Column("scope_id", sa.Text(), nullable=False),
        sa.Column("account_id", sa.Text(), nullable=True),
        sa.Column("region", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column(
            "tags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("raw_config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("config_hash", postgresql.BYTEA(), nullable=False),
        sa.Column(
            "first_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_seen_scan_id", sa.UUID(), nullable=False),
        sa.Column("deleted_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_id"],
            ["skyline.integrations.tenant_id", "skyline.integrations.id"],
            name=op.f("fk_assets_tenant_id_integration_id_integrations"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "last_seen_scan_id"],
            ["skyline.scan_runs.tenant_id", "skyline.scan_runs.id"],
            name=op.f("fk_assets_tenant_id_last_seen_scan_id_scan_runs"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_assets_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_assets_tenant_id_id")),
        sa.UniqueConstraint(
            "tenant_id",
            "integration_id",
            "native_id",
            name=op.f("uq_assets_tenant_id_integration_id_native_id"),
        ),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_assets_tenant_id_resource_type"),
        "assets",
        ["tenant_id", "resource_type"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("check_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Numeric(precision=6, scale=2), nullable=False),
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "first_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("resolved_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("reopened_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("last_scan_run_id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name=op.f("ck_findings_severity"),
        ),
        sa.CheckConstraint("status IN ('open', 'resolved')", name=op.f("ck_findings_status")),
        sa.CheckConstraint("reopened_count >= 0", name=op.f("ck_findings_reopened_count")),
        sa.ForeignKeyConstraint(
            ["check_id"], ["skyline.checks.id"], name=op.f("fk_findings_check_id_checks")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["skyline.assets.tenant_id", "skyline.assets.id"],
            name=op.f("fk_findings_tenant_id_asset_id_assets"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_id"],
            ["skyline.integrations.tenant_id", "skyline.integrations.id"],
            name=op.f("fk_findings_tenant_id_integration_id_integrations"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "last_scan_run_id"],
            ["skyline.scan_runs.tenant_id", "skyline.scan_runs.id"],
            name=op.f("fk_findings_tenant_id_last_scan_run_id_scan_runs"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_findings_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "tenant_id",
            "asset_id",
            "check_id",
            name=op.f("uq_findings_tenant_id_asset_id_check_id"),
        ),
        sa.UniqueConstraint("tenant_id", "id", name=op.f("uq_findings_tenant_id_id")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_findings_tenant_id_status_severity"),
        "findings",
        ["tenant_id", "status", "severity"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "relationships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("src_asset_id", sa.UUID(), nullable=False),
        sa.Column("dst_asset_id", sa.UUID(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column(
            "properties",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "first_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_seen_scan_id", sa.UUID(), nullable=False),
        sa.Column("deleted_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "dst_asset_id"],
            ["skyline.assets.tenant_id", "skyline.assets.id"],
            name=op.f("fk_relationships_tenant_id_dst_asset_id_assets"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_id"],
            ["skyline.integrations.tenant_id", "skyline.integrations.id"],
            name=op.f("fk_relationships_tenant_id_integration_id_integrations"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "last_seen_scan_id"],
            ["skyline.scan_runs.tenant_id", "skyline.scan_runs.id"],
            name=op.f("fk_relationships_tenant_id_last_seen_scan_id_scan_runs"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "src_asset_id"],
            ["skyline.assets.tenant_id", "skyline.assets.id"],
            name=op.f("fk_relationships_tenant_id_src_asset_id_assets"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_relationships_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_relationships")),
        sa.UniqueConstraint(
            "tenant_id",
            "src_asset_id",
            "dst_asset_id",
            "type",
            name=op.f("uq_relationships_tenant_id_src_asset_id_dst_asset_id_type"),
        ),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_relationships_tenant_id_dst_asset_id"),
        "relationships",
        ["tenant_id", "dst_asset_id"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "exceptions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("scope_type", sa.Text(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=True),
        sa.Column("check_id", sa.Text(), nullable=True),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=False),
        sa.Column("approved_by", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.UUID(), nullable=True),
        sa.CheckConstraint(
            "(scope_type = 'finding' AND finding_id IS NOT NULL AND check_id IS NULL AND asset_id IS NULL) OR (scope_type = 'check' AND check_id IS NOT NULL AND finding_id IS NULL AND asset_id IS NULL) OR (scope_type = 'asset' AND asset_id IS NOT NULL AND finding_id IS NULL AND check_id IS NULL) OR (scope_type = 'check_on_asset' AND check_id IS NOT NULL AND asset_id IS NOT NULL AND finding_id IS NULL)",
            name=op.f("ck_exceptions_scope_columns"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at AND expires_at <= created_at + interval '365 days'",
            name=op.f("ck_exceptions_expiry"),
        ),
        sa.CheckConstraint(
            "scope_type IN ('finding', 'check', 'asset', 'check_on_asset')",
            name=op.f("ck_exceptions_scope_type"),
        ),
        sa.CheckConstraint(
            "length(justification) BETWEEN 10 AND 2000", name=op.f("ck_exceptions_justification")
        ),
        sa.ForeignKeyConstraint(
            ["check_id"], ["skyline.checks.id"], name=op.f("fk_exceptions_check_id_checks")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "approved_by"],
            ["skyline.memberships.tenant_id", "skyline.memberships.user_id"],
            name=op.f("fk_exceptions_tenant_id_approved_by_memberships"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["skyline.assets.tenant_id", "skyline.assets.id"],
            name=op.f("fk_exceptions_tenant_id_asset_id_assets"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            ["skyline.memberships.tenant_id", "skyline.memberships.user_id"],
            name=op.f("fk_exceptions_tenant_id_created_by_memberships"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["skyline.findings.tenant_id", "skyline.findings.id"],
            name=op.f("fk_exceptions_tenant_id_finding_id_findings"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "revoked_by"],
            ["skyline.memberships.tenant_id", "skyline.memberships.user_id"],
            name=op.f("fk_exceptions_tenant_id_revoked_by_memberships"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_exceptions_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exceptions")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_exceptions_tenant_id_scope_type"),
        "exceptions",
        ["tenant_id", "scope_type"],
        unique=False,
        schema="skyline",
    )
    op.create_table(
        "finding_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("scan_run_id", sa.UUID(), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column(
            "at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "event IN ('new', 'still_open', 'auto_resolved', 'reopened')",
            name=op.f("ck_finding_events_event"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "finding_id"],
            ["skyline.findings.tenant_id", "skyline.findings.id"],
            name=op.f("fk_finding_events_tenant_id_finding_id_findings"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "scan_run_id"],
            ["skyline.scan_runs.tenant_id", "skyline.scan_runs.id"],
            name=op.f("fk_finding_events_tenant_id_scan_run_id_scan_runs"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["skyline.tenants.id"], name=op.f("fk_finding_events_tenant_id_tenants")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_events")),
        schema="skyline",
    )
    op.create_index(
        op.f("ix_finding_events_tenant_id_finding_id"),
        "finding_events",
        ["tenant_id", "finding_id"],
        unique=False,
        schema="skyline",
    )

    # Circular reference (tenants <-> secrets): added once both tables exist.
    op.create_foreign_key(
        "fk_tenants_redaction_key_secrets",
        "tenants",
        "secrets",
        ["id", "redaction_key_secret_id"],
        ["tenant_id", "id"],
        source_schema="skyline",
        referent_schema="skyline",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_tenants_redaction_key_secrets", "tenants", schema="skyline", type_="foreignkey"
    )
    op.drop_index(
        op.f("ix_finding_events_tenant_id_finding_id"),
        table_name="finding_events",
        schema="skyline",
    )
    op.drop_table("finding_events", schema="skyline")
    op.drop_index(
        op.f("ix_exceptions_tenant_id_scope_type"), table_name="exceptions", schema="skyline"
    )
    op.drop_table("exceptions", schema="skyline")
    op.drop_index(
        op.f("ix_relationships_tenant_id_dst_asset_id"),
        table_name="relationships",
        schema="skyline",
    )
    op.drop_table("relationships", schema="skyline")
    op.drop_index(
        op.f("ix_findings_tenant_id_status_severity"), table_name="findings", schema="skyline"
    )
    op.drop_table("findings", schema="skyline")
    op.drop_index(op.f("ix_assets_tenant_id_resource_type"), table_name="assets", schema="skyline")
    op.drop_table("assets", schema="skyline")
    op.drop_index(
        op.f("ix_scan_runs_tenant_id_integration_id_created_at"),
        table_name="scan_runs",
        schema="skyline",
    )
    op.drop_table("scan_runs", schema="skyline")
    op.drop_index(
        "uq_jobs_one_queued_verify",
        table_name="jobs",
        schema="skyline",
        postgresql_where=sa.text("kind = 'verify_integration' AND status = 'queued'"),
    )
    op.drop_index(
        "uq_jobs_one_active_scan",
        table_name="jobs",
        schema="skyline",
        postgresql_where=sa.text("kind = 'scan' AND status IN ('queued', 'running')"),
    )
    op.drop_index(
        "ix_jobs_leases",
        table_name="jobs",
        schema="skyline",
        postgresql_where=sa.text("status = 'running'"),
    )
    op.drop_index(
        "ix_jobs_claimable",
        table_name="jobs",
        schema="skyline",
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.drop_table("jobs", schema="skyline")
    op.drop_index(op.f("ix_sessions_user_id"), table_name="sessions", schema="skyline")
    op.drop_table("sessions", schema="skyline")
    op.drop_table("integrations", schema="skyline")
    op.drop_table("check_control_map", schema="skyline")
    op.drop_table("secrets", schema="skyline")
    op.drop_table("memberships", schema="skyline")
    op.drop_table("controls", schema="skyline")
    op.drop_index(op.f("ix_audit_log_tenant_id_at"), table_name="audit_log", schema="skyline")
    op.drop_table("audit_log", schema="skyline")
    op.drop_table("users", schema="skyline")
    op.drop_table("tenants", schema="skyline")
    op.drop_index(
        op.f("ix_login_attempts_subject_type_subject_hash_at"),
        table_name="login_attempts",
        schema="skyline",
    )
    op.drop_index(op.f("ix_login_attempts_at"), table_name="login_attempts", schema="skyline")
    op.drop_table("login_attempts", schema="skyline")
    op.drop_table("frameworks", schema="skyline")
    op.drop_table("checks", schema="skyline")
