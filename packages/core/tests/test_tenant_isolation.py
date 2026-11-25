"""Tenant isolation (CLAUDE.md rule 5): cross-tenant reads and writes must fail.

These run as the real application roles against the migrated schema, so they exercise
Row-Level Security, grants and the composite tenant foreign keys together.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from skyline_core.crypto import LocalKeyProvider, SecretPurpose, SecretSealer
from skyline_core.db.models import (
    AuditLog,
    Check,
    FindingException,
    Integration,
    IntegrationStatus,
    Job,
    Membership,
    ScanRun,
    Secret,
    Session,
    Tenant,
    User,
)
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.secrets_store import store_secret
from skyline_core.security.passwords import hash_password
from testsupport import Database, TenantFixture, rewind_login_attempts

pytestmark = pytest.mark.db

ROLES = ("skyline_api", "skyline_worker")


async def _integration(db: Database, tenant: TenantFixture) -> UUID:
    integration_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(Integration).values(
                id=integration_id,
                tenant_id=tenant.id,
                provider="fake",
                name="demo",
                status=IntegrationStatus.VERIFYING.value,
            )
        )
    # Only the worker may mark an integration connected (ADR-0011).
    async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
        await session.execute(
            update(Integration)
            .where(Integration.id == integration_id)
            .values(status=IntegrationStatus.CONNECTED.value)
        )
    return integration_id


@pytest.mark.parametrize("role", ROLES)
async def test_cross_tenant_select_returns_nothing(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture, role: str
) -> None:
    mine = await _integration(db, tenant)
    theirs = await _integration(db, other_tenant)
    async with tenant_scope(db.factory(role), tenant.id) as session:
        ids = set((await session.execute(select(Integration.id))).scalars())
        assert mine in ids
        assert theirs not in ids
        # Even asking explicitly for the other tenant's row by ID and tenant returns nothing.
        explicit = await session.execute(
            select(Integration).where(
                Integration.id == theirs, Integration.tenant_id == other_tenant.id
            )
        )
        assert explicit.first() is None


@pytest.mark.parametrize("role", ROLES)
async def test_cross_tenant_update_and_delete_affect_nothing(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture, role: str
) -> None:
    theirs = await _integration(db, other_tenant)
    async with tenant_scope(db.factory(role), tenant.id) as session:
        result = await session.execute(
            update(Integration).where(Integration.id == theirs).values(status_detail="pwned")
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]
    async with tenant_scope(db.factory("skyline_api"), other_tenant.id) as session:
        detail = (
            await session.execute(select(Integration.status_detail).where(Integration.id == theirs))
        ).scalar()
        assert detail == ""


async def test_api_cannot_delete_integrations_at_all(db: Database, tenant: TenantFixture) -> None:
    mine = await _integration(db, tenant)
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(delete(Integration).where(Integration.id == mine))


@pytest.mark.parametrize("role", ROLES)
async def test_cross_tenant_insert_is_rejected(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture, role: str
) -> None:
    integration_id = await _integration(db, tenant)
    with pytest.raises(ProgrammingError, match="row-level security"):
        async with tenant_scope(db.factory(role), tenant.id) as session:
            await session.execute(
                insert(ScanRun).values(
                    id=uuid4(),
                    tenant_id=other_tenant.id,
                    integration_id=integration_id,
                    trigger="manual",
                )
            )


async def test_composite_fk_blocks_cross_tenant_references(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    theirs = await _integration(db, other_tenant)
    # Own tenant_id passes RLS, but the referenced integration belongs to someone else.
    with pytest.raises(IntegrityError):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                insert(ScanRun).values(
                    id=uuid4(), tenant_id=tenant.id, integration_id=theirs, trigger="manual"
                )
            )


@pytest.mark.parametrize("role", (*ROLES, "skyline_owner"))
async def test_no_tenant_context_fails_closed(
    db: Database, tenant: TenantFixture, role: str
) -> None:
    await _integration(db, tenant)
    async with system_scope(db.factory(role)) as session:
        count = (await session.execute(select(func.count()).select_from(Integration))).scalar()
        assert count == 0


async def test_malformed_tenant_setting_errors(db: Database) -> None:
    with pytest.raises(DBAPIError):
        async with system_scope(db.factory("skyline_api")) as session:
            await session.execute(select(func.set_config("app.tenant_id", "not-a-uuid", True)))
            await session.execute(select(Integration.id))


async def test_tenant_setting_does_not_leak_between_transactions(
    db: Database, tenant: TenantFixture
) -> None:
    await _integration(db, tenant)
    factory = db.factory("skyline_api")
    async with tenant_scope(factory, tenant.id) as session:
        assert (await session.execute(select(func.count()).select_from(Integration))).scalar()
    for _ in range(3):  # pooled connections must not keep the setting
        async with system_scope(factory) as session:
            setting = (
                await session.execute(select(func.current_setting("app.tenant_id", True)))
            ).scalar()
            assert setting in (None, "")


async def test_read_only_scope_rejects_writes(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(DBAPIError, match="read-only transaction"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id, read_only=True) as session:
            await _insert_integration(session, tenant.id)


async def _insert_integration(session: object, tenant_id: UUID) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    assert isinstance(session, AsyncSession)
    await session.execute(
        insert(Integration).values(
            id=uuid4(), tenant_id=tenant_id, provider="fake", name="x", status="connected"
        )
    )


async def test_api_cannot_read_secret_material(db: Database, tenant: TenantFixture) -> None:
    sealer = SecretSealer(LocalKeyProvider({"k": secrets.token_bytes(32)}, "k"))
    factory = db.factory("skyline_api")
    async with tenant_scope(factory, tenant.id) as session:
        secret_id = await store_secret(
            session,
            sealer,
            tenant_id=tenant.id,
            purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
            plaintext=b"credential",
        )
    async with tenant_scope(factory, tenant.id) as session:
        purpose = (
            await session.execute(select(Secret.purpose).where(Secret.id == secret_id))
        ).scalar()
        assert purpose == "integration_credential"
    for column in (Secret.ciphertext, Secret.wrapped_dek, Secret.nonce):
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with tenant_scope(factory, tenant.id) as session:
                await session.execute(select(column))
    async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
        assert (
            await session.execute(select(Secret.ciphertext).where(Secret.id == secret_id))
        ).scalar()


@pytest.mark.parametrize("statement", ["update", "delete"])
@pytest.mark.parametrize("role", ROLES)
async def test_audit_log_is_append_only(
    db: Database, tenant: TenantFixture, role: str, statement: str
) -> None:
    query = update(AuditLog).values(action="x") if statement == "update" else delete(AuditLog)
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory(role), tenant.id) as session:
            await session.execute(query)


async def test_worker_cannot_touch_identity_tables(db: Database, tenant: TenantFixture) -> None:
    for table in (User, Session, Membership):
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
                await session.execute(select(func.count()).select_from(table))


async def test_api_cannot_read_password_hashes_directly(db: Database) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with system_scope(db.factory("skyline_api")) as session:
            await session.execute(select(User.password_hash))


async def test_api_cannot_read_or_claim_jobs(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(select(Job.id))


async def test_auth_lookup_returns_only_active_memberships(
    db: Database, tenant: TenantFixture
) -> None:
    async with system_scope(db.factory("skyline_api")) as session:
        rows = (
            await session.execute(
                text("SELECT * FROM skyline.auth_lookup_user(:email)"),
                {"email": tenant.admin_email},
            )
        ).all()
        assert [(r.user_id, r.tenant_id, r.role) for r in rows] == [
            (tenant.admin_id, tenant.id, "admin")
        ]
        unknown = await session.execute(
            text("SELECT * FROM skyline.auth_lookup_user('nobody@example.com')")
        )
        assert unknown.first() is None
    async with system_scope(db.factory("skyline_owner")) as session:
        await session.execute(
            update(User).where(User.id == tenant.admin_id).values(status="disabled")
        )
    async with system_scope(db.factory("skyline_api")) as session:
        disabled = await session.execute(
            text("SELECT * FROM skyline.auth_lookup_user(:email)"), {"email": tenant.admin_email}
        )
        assert disabled.first() is None


async def test_users_are_visible_only_within_the_tenant(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        ids = set((await session.execute(select(User.id))).scalars())
        assert ids == {tenant.admin_id}
        emails = set((await session.execute(select(User.email))).scalars())
        assert other_tenant.admin_email not in emails
    async with system_scope(db.factory("skyline_api")) as session:
        assert (await session.execute(select(func.count()).select_from(User))).scalar() == 0
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
            await session.execute(select(User.id))


async def test_api_cannot_change_another_tenants_user(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        result = await session.execute(
            update(User).where(User.id == other_tenant.admin_id).values(last_login_at=func.now())
        )
        assert result.rowcount == 0  # type: ignore[attr-defined]
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                update(User).where(User.id == tenant.admin_id).values(password_hash="x")
            )


@dataclass(frozen=True)
class _Sess:
    id: UUID
    token_hash: bytes


async def _session(db: Database, tenant: TenantFixture, *, expires_in: timedelta) -> _Sess:
    sess = _Sess(id=uuid4(), token_hash=secrets.token_bytes(32))
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(Session).values(
                id=sess.id,
                tenant_id=tenant.id,
                user_id=tenant.admin_id,
                token_hash=sess.token_hash,
                expires_at=datetime.now(UTC) + expires_in,
            )
        )
    return sess


async def _resolve(db: Database, sess: _Sess | bytes) -> Any:
    token_hash = sess if isinstance(sess, bytes) else sess.token_hash
    async with system_scope(db.factory("skyline_api")) as session:
        return (
            await session.execute(
                text("SELECT * FROM skyline.resolve_session(:h, interval '30 minutes')"),
                {"h": token_hash},
            )
        ).first()


async def _change_password(db: Database, token_hash: bytes, new_hash: str) -> Any:
    async with system_scope(db.factory("skyline_api")) as session:
        return (
            await session.execute(
                text("SELECT skyline.change_password(:h, :p, interval '30 minutes')"),
                {"h": token_hash, "p": new_hash},
            )
        ).scalar()


async def _update_session(db: Database, tenant: TenantFixture, sess: _Sess, **values: Any) -> None:
    async with tenant_scope(db.factory("skyline_owner"), tenant.id) as session:
        await session.execute(update(Session).where(Session.id == sess.id).values(**values))


async def test_resolve_session_fails_closed(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    live = await _session(db, tenant, expires_in=timedelta(hours=1))
    row = await _resolve(db, live)
    assert (row.tenant_id, row.user_id, row.role) == (tenant.id, tenant.admin_id, "admin")
    assert await _resolve(db, secrets.token_bytes(32)) is None
    expired = await _session(db, tenant, expires_in=timedelta(seconds=-1))
    assert await _resolve(db, expired) is None
    revoked = await _session(db, tenant, expires_in=timedelta(hours=1))
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            update(Session).where(Session.id == revoked.id).values(revoked_at=func.now())
        )
    assert await _resolve(db, revoked) is None
    # Idle sessions stop resolving (the owner backdates last_seen_at; the API can't).
    idle = await _session(db, tenant, expires_in=timedelta(hours=1))
    async with tenant_scope(db.factory("skyline_owner"), tenant.id) as session:
        await session.execute(text("ALTER TABLE skyline.sessions DISABLE TRIGGER sessions_guard"))
        await session.execute(
            update(Session)
            .where(Session.id == idle.id)
            .values(last_seen_at=datetime.now(UTC) - timedelta(hours=1))
        )
        await session.execute(text("ALTER TABLE skyline.sessions ENABLE TRIGGER sessions_guard"))
    assert await _resolve(db, idle) is None
    assert await _change_password(db, idle.token_hash, hash_password("x" * 12 + "yz")) is None
    # Suspending the tenant or disabling the user kills live sessions at once.
    other_live = await _session(db, other_tenant, expires_in=timedelta(hours=1))
    async with system_scope(db.factory("skyline_owner")) as session:
        await session.execute(
            update(Tenant).where(Tenant.id == other_tenant.id).values(status="suspended")
        )
        await session.execute(
            update(User).where(User.id == tenant.admin_id).values(status="disabled")
        )
    assert await _resolve(db, other_live) is None
    assert await _resolve(db, live) is None


async def test_api_cannot_read_token_hashes(db: Database, tenant: TenantFixture) -> None:
    await _session(db, tenant, expires_in=timedelta(hours=1))
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(select(Session.token_hash))


async def test_api_cannot_extend_or_reassign_sessions(db: Database, tenant: TenantFixture) -> None:
    sess = await _session(db, tenant, expires_in=timedelta(hours=1))
    changes: list[dict[str, Any]] = [
        {"expires_at": datetime.now(UTC) + timedelta(days=30)},
        {"user_id": uuid4()},
        {"token_hash": secrets.token_bytes(32)},
    ]
    for values in changes:
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
                await session.execute(update(Session).where(Session.id == sess.id).values(**values))


async def test_sessions_cannot_be_unrevoked_or_kept_alive_into_the_future(
    db: Database, tenant: TenantFixture
) -> None:
    sess = await _session(db, tenant, expires_in=timedelta(hours=1))
    api = db.factory("skyline_api")
    async with tenant_scope(api, tenant.id) as session:
        await session.execute(
            update(Session)
            .where(Session.id == sess.id)
            .values(last_seen_at=datetime.now(UTC) + timedelta(days=1))
        )
        seen = (
            await session.execute(select(Session.last_seen_at).where(Session.id == sess.id))
        ).scalar_one()
    assert seen <= datetime.now(UTC) + timedelta(seconds=5)
    async with tenant_scope(api, tenant.id) as session:
        await session.execute(
            update(Session)
            .where(Session.id == sess.id)
            .values(revoked_at=datetime.now(UTC) + timedelta(days=1))
        )
        revoked_at = (
            await session.execute(select(Session.revoked_at).where(Session.id == sess.id))
        ).scalar_one()
    assert revoked_at is not None
    assert revoked_at <= datetime.now(UTC) + timedelta(seconds=5)
    with pytest.raises(ProgrammingError, match="revoked session"):
        async with tenant_scope(api, tenant.id) as session:
            await session.execute(
                update(Session).where(Session.id == sess.id).values(revoked_at=None)
            )


async def test_sessions_have_a_maximum_lifetime(db: Database, tenant: TenantFixture) -> None:
    with pytest.raises(IntegrityError):
        await _session(db, tenant, expires_in=timedelta(hours=13))


async def test_change_password_is_bound_to_the_session(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    mine = await _session(db, tenant, expires_in=timedelta(hours=1))
    second = await _session(db, tenant, expires_in=timedelta(hours=1))
    theirs = await _session(db, other_tenant, expires_in=timedelta(hours=1))
    new_hash = hash_password(secrets.token_urlsafe(16))
    assert await _change_password(db, mine.token_hash, new_hash) == tenant.admin_id
    assert await _change_password(db, secrets.token_bytes(32), new_hash) is None
    # Every session of that user is revoked; other users are untouched.
    assert await _resolve(db, mine) is None
    assert await _resolve(db, second) is None
    assert await _resolve(db, theirs) is not None
    async with system_scope(db.factory("skyline_api")) as session:
        row = (
            await session.execute(
                text("SELECT * FROM skyline.auth_lookup_user(:e)"), {"e": tenant.admin_email}
            )
        ).one()
    assert row.password_hash == new_hash
    assert row.must_change_password is False


@pytest.mark.parametrize("bad_hash", ["plaintext-password", "", "$argon2id$" + "x" * 600])
async def test_change_password_rejects_non_argon2_hashes(
    db: Database, tenant: TenantFixture, bad_hash: str
) -> None:
    sess = await _session(db, tenant, expires_in=timedelta(hours=1))
    with pytest.raises(DBAPIError, match="invalid password hash"):
        await _change_password(db, sess.token_hash, bad_hash)


async def test_api_cannot_mark_an_integration_connected(
    db: Database, tenant: TenantFixture
) -> None:
    with pytest.raises(ProgrammingError):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                insert(Integration).values(
                    id=uuid4(), tenant_id=tenant.id, provider="fake", name="x", status="connected"
                )
            )
    verifying = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(Integration).values(
                id=verifying, tenant_id=tenant.id, provider="fake", name="x", status="verifying"
            )
        )
    with pytest.raises(ProgrammingError, match="only the worker"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                update(Integration).where(Integration.id == verifying).values(status="connected")
            )
    connected = await _integration(db, tenant)
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        # Renaming keeps it connected; changing its config sends it back to verification.
        await session.execute(
            update(Integration).where(Integration.id == connected).values(name="renamed")
        )
        assert (
            await session.execute(select(Integration.status).where(Integration.id == connected))
        ).scalar() == "connected"
        await session.execute(
            update(Integration)
            .where(Integration.id == connected)
            .values(config={"simulate_fixes": ["enable_mfa"]})
        )
        assert (
            await session.execute(select(Integration.status).where(Integration.id == connected))
        ).scalar() == "verifying"


async def test_external_ids_are_generated_unique_and_not_client_settable(
    db: Database, tenant: TenantFixture, other_tenant: TenantFixture
) -> None:
    first = await _integration(db, tenant)
    second = await _integration(db, other_tenant)
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        mine = (
            await session.execute(select(Integration.external_id).where(Integration.id == first))
        ).scalar_one()
    async with tenant_scope(db.factory("skyline_api"), other_tenant.id) as session:
        theirs = (
            await session.execute(select(Integration.external_id).where(Integration.id == second))
        ).scalar_one()
    assert len(mine) == 64 and mine != theirs
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                insert(Integration).values(
                    id=uuid4(),
                    tenant_id=tenant.id,
                    provider="fake",
                    name="x",
                    status="verifying",
                    external_id=theirs,
                )
            )
    with pytest.raises(IntegrityError):
        async with tenant_scope(db.factory("skyline_owner"), tenant.id) as session:
            await session.execute(
                update(Integration).where(Integration.id == first).values(external_id=theirs)
            )


async def test_exceptions_cannot_be_unrevoked(db: Database, tenant: TenantFixture) -> None:
    async with system_scope(db.factory("skyline_owner")) as session:
        await session.execute(
            pg_insert(Check)
            .values(
                id="fake.test.exception_guard",
                version=1,
                provider="fake",
                severity="low",
                title="t",
                meta={},
                content_hash=b"h",
            )
            .on_conflict_do_nothing()
        )
    exception_id = uuid4()
    api = db.factory("skyline_api")
    async with tenant_scope(api, tenant.id) as session:
        await session.execute(
            insert(FindingException).values(
                id=exception_id,
                tenant_id=tenant.id,
                scope_type="check",
                check_id="fake.test.exception_guard",
                justification="accepted for the test",
                created_by=tenant.admin_id,
                approved_by=tenant.admin_id,
                expires_at=datetime.now(UTC) + timedelta(days=30),
            )
        )
        await session.execute(
            update(FindingException)
            .where(FindingException.id == exception_id)
            .values(revoked_at=func.now(), revoked_by=tenant.admin_id)
        )
    with pytest.raises(ProgrammingError, match="revoked exception"):
        async with tenant_scope(api, tenant.id) as session:
            await session.execute(
                update(FindingException)
                .where(FindingException.id == exception_id)
                .values(revoked_at=None)
            )


async def test_api_cannot_set_job_state_or_schedule(db: Database, tenant: TenantFixture) -> None:
    integration_id = await _integration(db, tenant)
    extras: list[dict[str, Any]] = [
        {"status": "running"},
        {"locked_by": "x"},
        {"attempts": 5},
        {"run_at": datetime.now(UTC)},
    ]
    for extra in extras:
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
                await session.execute(
                    insert(Job).values(
                        id=uuid4(),
                        tenant_id=tenant.id,
                        kind="verify_integration",
                        integration_id=integration_id,
                        payload={"integration_id": str(integration_id)},
                        **extra,
                    )
                )


async def test_worker_cannot_rewrite_job_identity(db: Database) -> None:
    changes: list[dict[str, Any]] = [{"tenant_id": uuid4()}, {"payload": {}}, {"kind": "scan"}]
    for values in changes:
        with pytest.raises(ProgrammingError, match="permission denied"):
            async with system_scope(db.factory("skyline_worker")) as session:
                await session.execute(update(Job).values(**values))


async def test_database_and_membership_privileges(db: Database) -> None:
    async with db.engine("skyline_owner").connect() as conn:
        public_connect = (
            await conn.execute(
                text("SELECT has_database_privilege('public', current_database(), 'CONNECT')")
            )
        ).scalar()
        public_temp = (
            await conn.execute(
                text("SELECT has_database_privilege('public', current_database(), 'TEMP')")
            )
        ).scalar()
        members = (
            await conn.execute(
                text(
                    "SELECT r.rolname AS role, m.rolname AS member, a.inherit_option,"
                    " a.set_option FROM pg_auth_members a"
                    " JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member"
                    " WHERE r.rolname LIKE 'skyline_%' OR m.rolname LIKE 'skyline_%'"
                )
            )
        ).all()
    assert public_connect is False
    assert public_temp is False
    assert [(r.role, r.member, r.inherit_option, r.set_option) for r in members] == [
        ("skyline_definer", "skyline_owner", False, True)
    ]


async def test_worker_cannot_call_api_definer_functions(db: Database) -> None:
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with system_scope(db.factory("skyline_worker")) as session:
            await session.execute(text("SELECT * FROM skyline.auth_lookup_user('x@example.com')"))


async def test_due_integrations_returns_ids_only(db: Database, tenant: TenantFixture) -> None:
    integration_id = await _integration(db, tenant)
    async with tenant_scope(db.factory("skyline_worker"), tenant.id) as session:
        await session.execute(
            update(Integration)
            .where(Integration.id == integration_id)
            .values(next_scan_at=datetime.now(UTC) - timedelta(minutes=1))
        )
    async with system_scope(db.factory("skyline_worker")) as session:
        rows = (await session.execute(text("SELECT * FROM skyline.due_integrations(1000)"))).all()
    assert (tenant.id, integration_id) in [(r.tenant_id, r.integration_id) for r in rows]
    assert all(len(r) == 2 for r in rows)


#: begin_login_attempt with progressive waits off: only the sliding-window ceiling applies.
_CEILING_ONLY = (
    "SELECT * FROM skyline.begin_login_attempt(:a, 3, :i, 100, interval '5 minutes',"
    " interval '0', interval '0', interval '15 minutes')"
)
#: The API defaults: waits double from 1 s to a 300 s lock; 60 quiet minutes end a streak;
#: a hard ceiling of 10 failures per 5 minutes.
_WAITS = (
    "SELECT * FROM skyline.begin_login_attempt(:a, 10, NULL, NULL, interval '5 minutes',"
    " interval '1 second', interval '300 seconds', interval '60 minutes')"
)


async def _try_login(db: Database, account: bytes) -> Any:
    async with system_scope(db.factory("skyline_api")) as session:
        return (await session.execute(text(_WAITS), {"a": account})).one()


async def _finish(db: Database, ids: list[int], outcome: str) -> None:
    async with system_scope(db.factory("skyline_api")) as session:
        await session.execute(
            text("SELECT skyline.finish_login_attempt(:ids, :o)"), {"ids": ids, "o": outcome}
        )


async def test_login_waits_double_up_to_a_temporary_lock(db: Database) -> None:
    account = secrets.token_bytes(32)
    expected = [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300]
    for wait in expected:
        assert (await _try_login(db, account)).allowed  # a guess, reserved as a failure
        refused = await _try_login(db, account)
        assert not refused.allowed and refused.attempt_ids == []
        assert wait - 1 <= refused.retry_after <= wait
        await rewind_login_attempts(db, wait)


async def test_refused_attempts_never_extend_the_lock(db: Database) -> None:
    account = secrets.token_bytes(32)
    for wait in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
        assert (await _try_login(db, account)).allowed
        await rewind_login_attempts(db, wait)
    assert (await _try_login(db, account)).allowed  # 10th failure: the 300 s lock starts
    retries = [(await _try_login(db, account)).retry_after for _ in range(20)]
    assert retries == sorted(retries, reverse=True) and 299 <= retries[0] <= 300
    async with system_scope(db.factory("skyline_owner")) as session:
        rows = await session.execute(
            text("SELECT count(*) FROM skyline.login_attempts WHERE subject_hash = :a"),
            {"a": account},
        )
        assert rows.scalar() == 10  # the 20 refusals left no trace
    await rewind_login_attempts(db, 300)
    assert (await _try_login(db, account)).allowed  # expired on its own


async def test_a_quiet_period_or_a_success_ends_the_streak(db: Database) -> None:
    account = secrets.token_bytes(32)
    for wait in [1, 2, 4, 8]:
        assert (await _try_login(db, account)).allowed
        await rewind_login_attempts(db, wait)
    assert (await _try_login(db, account)).allowed
    assert (await _try_login(db, account)).retry_after >= 15  # 5th failure: 16 s
    await rewind_login_attempts(db, 60 * 60 + 1)  # an hour without a failure
    assert (await _try_login(db, account)).allowed
    assert (await _try_login(db, account)).retry_after == 1  # a new streak
    await rewind_login_attempts(db, 1)
    ok = await _try_login(db, account)
    await _finish(db, list(ok.attempt_ids), "succeeded")
    assert (await _try_login(db, account)).allowed  # no wait after a success
    assert (await _try_login(db, account)).retry_after == 1


async def test_the_real_users_sign_ins_dont_reset_the_ceiling(db: Database) -> None:
    """Each success ends the wait streak, so the attacker could guess again at once; the
    ceiling still caps failures at 10 in 5 minutes (Cyber Essentials v3.3)."""
    account = secrets.token_bytes(32)
    failures = 0
    for _ in range(15):
        guess = await _try_login(db, account)
        if not guess.allowed:
            break
        failures += 1
        await rewind_login_attempts(db, 1)
        user = await _try_login(db, account)  # the real user signs in in between
        if user.allowed:
            await _finish(db, list(user.attempt_ids), "succeeded")
    assert failures == 10


@pytest.mark.parametrize("window", [0, -60, None])
async def test_the_window_must_be_positive(db: Database, window: int | None) -> None:
    with pytest.raises(DBAPIError, match="positive limits"):
        async with system_scope(db.factory("skyline_api")) as session:
            await session.execute(
                text(
                    "SELECT * FROM skyline.begin_login_attempt(:a, 10, NULL, NULL,"
                    " make_interval(secs => :w), interval '1 second', interval '300 seconds',"
                    " interval '60 minutes')"
                ),
                {"a": secrets.token_bytes(32), "w": window},
            )


async def test_a_cancelled_reservation_releases_its_wait(db: Database) -> None:
    account = secrets.token_bytes(32)
    reserved = await _try_login(db, account)
    assert not (await _try_login(db, account)).allowed
    await _finish(db, list(reserved.attempt_ids), "cancelled")
    assert (await _try_login(db, account)).allowed


@pytest.mark.parametrize(
    ("base", "cap", "reset"),
    [
        (-1, 300, 900),  # negative first wait
        (10, 5, 900),  # cap below the first wait
        (1, 300, 300),  # streak forgotten before the lock ends
        (0, 0, 0),  # no streak at all
        (1, 300, None),
        (None, 300, 900),
    ],
)
async def test_invalid_wait_settings_are_rejected(
    db: Database, base: int | None, cap: int, reset: int | None
) -> None:
    with pytest.raises(DBAPIError, match="invalid wait settings"):
        async with system_scope(db.factory("skyline_api")) as session:
            await session.execute(
                text(
                    "SELECT * FROM skyline.begin_login_attempt(:a, 10, NULL, NULL,"
                    " interval '5 minutes', make_interval(secs => :b),"
                    " make_interval(secs => :c), make_interval(secs => :r))"
                ),
                {"a": secrets.token_bytes(32), "b": base, "c": cap, "r": reset},
            )


async def test_login_attempt_functions(db: Database) -> None:
    account, ip = secrets.token_bytes(32), secrets.token_bytes(32)
    factory = db.factory("skyline_api")
    begin = text(_CEILING_ONLY)
    async with system_scope(factory) as session:
        attempts = [(await session.execute(begin, {"a": account, "i": ip})).one() for _ in range(4)]
    # Three reservations fit the account budget of 3; the fourth is refused with a wait.
    assert [a.allowed for a in attempts] == [True, True, True, False]
    assert attempts[3].retry_after >= 1 and attempts[3].attempt_ids == []
    assert all(len(a.attempt_ids) == 2 for a in attempts[:3])  # account + IP rows
    async with system_scope(factory) as session:
        await session.execute(
            text("SELECT skyline.finish_login_attempt(:ids, 'succeeded')"),
            {"ids": attempts[0].attempt_ids},
        )
        # A success no longer counts as a failure (but doesn't reset the others).
        assert (await session.execute(begin, {"a": account, "i": ip})).one().allowed
        await session.execute(
            text("SELECT skyline.finish_login_attempt(:ids, 'cancelled')"),
            {"ids": attempts[1].attempt_ids},
        )
    with pytest.raises(DBAPIError, match="unknown outcome"):
        async with system_scope(factory) as session:
            await session.execute(
                text("SELECT skyline.finish_login_attempt(:ids, 'bogus')"), {"ids": [1]}
            )
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with system_scope(factory) as session:  # internal helper only
            await session.execute(
                text(
                    "SELECT * FROM skyline.recent_login_failures('account', :h,"
                    " interval '5 minutes', true)"
                ),
                {"h": account},
            )
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with system_scope(factory) as session:
            await session.execute(text("DELETE FROM skyline.login_attempts"))
    async with system_scope(db.factory("skyline_worker")) as session:
        purged = (await session.execute(text("SELECT skyline.purge_login_attempts()"))).scalar()
        assert isinstance(purged, int)


async def test_the_api_can_only_clear_an_integration_credential(
    db: Database, tenant: TenantFixture
) -> None:
    from skyline_core.db.models import Integration

    integration_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        await session.execute(
            insert(Integration).values(
                id=integration_id,
                tenant_id=tenant.id,
                provider="fake",
                name="x",
                status="verifying",
            )
        )
    with pytest.raises(ProgrammingError, match="can only be removed"):
        async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
            await session.execute(
                update(Integration)
                .where(Integration.id == integration_id)
                .values(credential_secret_id=uuid4())
            )
