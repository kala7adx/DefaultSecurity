"""First-run bootstrap (run by migrate as the owner role): default tenant and admin.

Idempotent: if any tenant exists nothing is created, but a tenant missing its redaction key
gets one. The admin must change the generated password on first login.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final
from uuid import UUID, uuid4

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from skyline_core.audit import AuditAction, record_audit
from skyline_core.crypto import SecretSealer
from skyline_core.db.models import ActorType, Membership, Role, Tenant, User
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.secrets_store import create_redaction_key
from skyline_core.security.passwords import check_password_policy, hash_password

_EMAIL: Final = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$")


class BootstrapError(ValueError):
    """Bootstrap settings are missing or invalid."""


def normalise_email(email: str) -> str:
    """Lower-case and validate an email address (no external validator, no DNS)."""
    value = email.strip().lower()
    if len(value) > 320 or not _EMAIL.match(value):  # noqa: PLR2004 - RFC 5321 limit
        msg = "invalid email address"
        raise BootstrapError(msg)
    return value


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    created: bool
    tenant_id: UUID | None
    redaction_keys_created: int


async def bootstrap(
    factory: async_sessionmaker[AsyncSession],
    sealer: SecretSealer,
    *,
    admin_email: str,
    admin_password: str | None,
    tenant_slug: str,
    tenant_name: str,
) -> BootstrapResult:
    async with system_scope(factory) as session:
        tenants = (await session.execute(select(Tenant.id, Tenant.redaction_key_secret_id))).all()
    keys_created = 0
    for tenant_id, key_id in tenants:
        if key_id is None:
            async with tenant_scope(factory, tenant_id) as session:
                await create_redaction_key(session, sealer, tenant_id=tenant_id)
            keys_created += 1
    if tenants:
        return BootstrapResult(created=False, tenant_id=None, redaction_keys_created=keys_created)

    if not admin_password:
        msg = "SKYLINE_BOOTSTRAP_ADMIN_PASSWORD_FILE is required for the first run"
        raise BootstrapError(msg)
    email = normalise_email(admin_email)
    check_password_policy(admin_password, email=email)
    tenant_id, user_id = uuid4(), uuid4()
    async with system_scope(factory) as session:
        await session.execute(
            insert(Tenant).values(id=tenant_id, slug=tenant_slug, name=tenant_name)
        )
        await session.execute(
            insert(User).values(
                id=user_id,
                email=email,
                password_hash=hash_password(admin_password),
                must_change_password=True,
            )
        )
    async with tenant_scope(factory, tenant_id) as session:
        await session.execute(
            insert(Membership).values(tenant_id=tenant_id, user_id=user_id, role=Role.ADMIN.value)
        )
        await create_redaction_key(session, sealer, tenant_id=tenant_id)
        await record_audit(
            session,
            action=AuditAction.BOOTSTRAP_COMPLETED,
            tenant_id=tenant_id,
            actor_type=ActorType.SYSTEM,
            target_type="tenant",
            target_id=tenant_id,
            details={"admin_user_id": str(user_id)},
        )
    return BootstrapResult(created=True, tenant_id=tenant_id, redaction_keys_created=1)
