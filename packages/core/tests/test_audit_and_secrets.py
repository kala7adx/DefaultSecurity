from __future__ import annotations

import secrets
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select
from sqlalchemy.exc import ProgrammingError

from skyline_core.audit import AuditAction, record_audit
from skyline_core.crypto import LocalKeyProvider, SecretOpener, SecretPurpose, SecretSealer
from skyline_core.db.models import ActorType, AuditLog, AuditOutcome, Secret
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.logging import bind_correlation_id, clear_context
from skyline_core.secrets_store import (
    SecretNotFoundError,
    create_redaction_key,
    load_secret,
    store_secret,
    tenant_redaction_key_id,
)
from testsupport import Database, TenantFixture

pytestmark = pytest.mark.db

PROVIDER = LocalKeyProvider({"k": secrets.token_bytes(32)}, "k")


async def test_audit_entries_are_redacted_and_tenant_scoped(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    secret = secrets.token_hex(8)
    bind_correlation_id("c0ffee00-0000-4000-8000-000000000001")
    api = db.factory("skyline_api")
    async with tenant_scope(api, tenant.id) as session:
        await record_audit(
            session,
            action=AuditAction.INTEGRATION_CREATED,
            tenant_id=tenant.id,
            actor_type=ActorType.USER,
            actor_id=tenant.admin_id,
            target_type="integration",
            target_id=uuid4(),
            details={"name": "demo", "api_key": secret, "nested": {"token": secret}},
            ip="203.0.113.7",
        )
    clear_context()
    async with tenant_scope(api, tenant.id) as session:
        row = (
            await session.execute(
                select(AuditLog).where(AuditLog.action == AuditAction.INTEGRATION_CREATED.value)
            )
        ).scalar_one()
    assert secret not in str(row.details)
    assert row.details["name"] == "demo"
    assert str(row.ip) == "203.0.113.7"
    assert row.correlation_id == "c0ffee00-0000-4000-8000-000000000001"
    async with tenant_scope(api, other_tenant.id) as session:
        count = (await session.execute(select(func.count()).select_from(AuditLog))).scalar()
    assert count == 0


async def test_preauth_events_are_writable_but_not_readable_by_apps(db: Database) -> None:
    api = db.factory("skyline_api")
    async with system_scope(api) as session:
        await record_audit(
            session,
            action=AuditAction.LOGIN_FAILED,
            tenant_id=None,
            actor_type=ActorType.ANONYMOUS,
            outcome=AuditOutcome.FAILURE,
            details={"reason": "unknown_user"},
            ip="not-an-ip",
        )
        visible = (await session.execute(select(func.count()).select_from(AuditLog))).scalar()
    assert visible == 0


@pytest.mark.parametrize(
    ("role", "action", "actor"),
    [
        ("skyline_api", AuditAction.BOOTSTRAP_COMPLETED, ActorType.SYSTEM),
        ("skyline_api", AuditAction.LOGIN_FAILED, ActorType.SYSTEM),
        ("skyline_worker", AuditAction.LOGIN_FAILED, ActorType.ANONYMOUS),
    ],
)
async def test_tenantless_audit_rows_cannot_be_forged(
    db: Database, role: str, action: AuditAction, actor: ActorType
) -> None:
    with pytest.raises(ProgrammingError, match="row-level security"):
        async with system_scope(db.factory(role)) as session:
            await record_audit(session, action=action, tenant_id=None, actor_type=actor)


async def test_audit_time_and_id_cannot_be_set_by_apps(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                insert(AuditLog.__table__)  # type: ignore[arg-type]
                .inline()
                .values(
                    tenant_id=tenant.id,
                    actor_type="system",
                    action="x",
                    outcome="success",
                    at=func.now() - func.make_interval(0, 0, 0, 10),
                )
            )


async def test_oversized_details_are_truncated(db: Database, tenant: TenantFixture) -> None:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await record_audit(
            session,
            action=AuditAction.SCAN_REQUESTED,
            tenant_id=tenant.id,
            actor_type=ActorType.SYSTEM,
            details={"blob": "x" * 10_000},
        )
        details = (
            await session.execute(
                select(AuditLog.details).where(AuditLog.action == AuditAction.SCAN_REQUESTED.value)
            )
        ).scalar_one()
    assert details == {"truncated": True}


async def test_api_seals_worker_opens(db: Database, tenant: TenantFixture) -> None:
    plaintext = secrets.token_bytes(24)
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        secret_id = await store_secret(
            session,
            SecretSealer(PROVIDER),
            tenant_id=tenant.id,
            purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
            plaintext=plaintext,
        )
    opener = SecretOpener(PROVIDER)
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await load_secret(
                session,
                opener,
                tenant_id=tenant.id,
                secret_id=secret_id,
                purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
            )
    async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
        opened = await load_secret(
            session,
            opener,
            tenant_id=tenant.id,
            secret_id=secret_id,
            purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
        )
        assert opened.reveal() == plaintext
        assert "***" in repr(opened)
        with pytest.raises(SecretNotFoundError):
            await load_secret(
                session,
                opener,
                tenant_id=tenant.id,
                secret_id=secret_id,
                purpose=SecretPurpose.REDACTION_HMAC_KEY,
            )


async def test_api_cannot_plant_a_redaction_key(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(ProgrammingError, match="row-level security"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await store_secret(
                session,
                SecretSealer(PROVIDER),
                tenant_id=tenant.id,
                purpose=SecretPurpose.REDACTION_HMAC_KEY,
                plaintext=b"attacker-chosen-key-material-123",
            )


async def test_api_cannot_backdate_or_postdate_secrets(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                insert(Secret).values(
                    id=uuid4(),
                    tenant_id=tenant.id,
                    purpose="integration_credential",
                    key_provider="local",
                    key_id="k",
                    wrapped_dek=b"x",
                    nonce=b"n" * 12,
                    ciphertext=b"c",
                    created_at=func.now() + func.make_interval(9999),
                )
            )


async def test_worker_cannot_write_secrets(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
            await store_secret(
                session,
                SecretSealer(PROVIDER),
                tenant_id=tenant.id,
                purpose=SecretPurpose.REDACTION_HMAC_KEY,
                plaintext=b"x" * 32,
            )


async def test_redaction_key_is_referenced_by_the_tenant(
    db: Database, tenant: TenantFixture
) -> None:
    async with tenant_scope(db.factory("skyline_owner"), tenant.id) as session:
        key_id = await create_redaction_key(session, SecretSealer(PROVIDER), tenant_id=tenant.id)
    async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
        assert await tenant_redaction_key_id(session, tenant_id=tenant.id) == key_id
        key = await load_secret(
            session,
            SecretOpener(PROVIDER),
            tenant_id=tenant.id,
            secret_id=key_id,
            purpose=SecretPurpose.REDACTION_HMAC_KEY,
        )
        assert len(key.reveal()) == 32
