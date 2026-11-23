"""Store and load envelope-encrypted secrets (the ``secrets`` table).

The API role has INSERT but no SELECT on key material, so only :func:`store_secret` works
there. :func:`load_secret` is for the worker (and migrate), which can read the row.
"""

from __future__ import annotations

import secrets
from uuid import UUID, uuid4

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_core.crypto import (
    EncryptionContext,
    SealedSecret,
    SecretOpener,
    SecretPurpose,
    SecretSealer,
)
from skyline_core.db.models import Secret, Tenant
from skyline_core.types import Sensitive


class SecretNotFoundError(LookupError):
    """No secret with that ID and purpose exists for the current tenant."""


async def store_secret(
    session: AsyncSession,
    sealer: SecretSealer,
    *,
    tenant_id: UUID,
    purpose: SecretPurpose,
    plaintext: bytes,
) -> UUID:
    """Seal ``plaintext`` and insert it. Returns the new secret ID (no RETURNING needed)."""
    secret_id = uuid4()
    ctx = EncryptionContext(tenant_id=tenant_id, secret_id=secret_id, purpose=purpose)
    sealed = await sealer.seal(plaintext, ctx)
    await session.execute(
        insert(Secret).values(
            id=secret_id,
            tenant_id=tenant_id,
            purpose=purpose.value,
            key_provider=sealed.key_provider,
            key_id=sealed.key_id,
            wrapped_dek=sealed.wrapped_dek,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
            format_version=sealed.format_version,
        )
    )
    return secret_id


async def load_secret(
    session: AsyncSession,
    opener: SecretOpener,
    *,
    tenant_id: UUID,
    secret_id: UUID,
    purpose: SecretPurpose,
) -> Sensitive[bytes]:
    """Load and decrypt one secret. The result is wrapped so it can't be logged by accident."""
    row = (
        await session.execute(
            select(Secret).where(
                Secret.tenant_id == tenant_id,
                Secret.id == secret_id,
                Secret.purpose == purpose.value,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise SecretNotFoundError(secret_id)
    sealed = SealedSecret(
        key_provider=row.key_provider,
        key_id=row.key_id,
        wrapped_dek=row.wrapped_dek,
        nonce=row.nonce,
        ciphertext=row.ciphertext,
        format_version=row.format_version,
    )
    ctx = EncryptionContext(tenant_id=tenant_id, secret_id=secret_id, purpose=purpose)
    return Sensitive(await opener.open(sealed, ctx))


async def tenant_redaction_key_id(session: AsyncSession, *, tenant_id: UUID) -> UUID | None:
    """The tenant's redaction HMAC key, by the fixed reference on ``tenants`` (never "newest")."""
    return (
        await session.execute(select(Tenant.redaction_key_secret_id).where(Tenant.id == tenant_id))
    ).scalar_one_or_none()


async def create_redaction_key(
    session: AsyncSession, sealer: SecretSealer, *, tenant_id: UUID
) -> UUID:
    """Generate and store a tenant's redaction HMAC key and point the tenant at it.

    Only the owner role (bootstrap / tenant creation) can do this: the API may only seal
    integration credentials (RESTRICTIVE policy) and the worker can't write ``secrets``.
    ``session`` must be bound to ``tenant_id``.
    """
    secret_id = await store_secret(
        session,
        sealer,
        tenant_id=tenant_id,
        purpose=SecretPurpose.REDACTION_HMAC_KEY,
        plaintext=secrets.token_bytes(32),
    )
    await session.execute(
        update(Tenant).where(Tenant.id == tenant_id).values(redaction_key_secret_id=secret_id)
    )
    return secret_id
