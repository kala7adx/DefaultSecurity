"""Turn a stored integration into a ready connector. Credentials live in memory for one job."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_connectors.registry import ConnectorSpec, UnknownProviderError, get_spec
from skyline_core.crypto import CryptoError, SecretPurpose
from skyline_core.db.models import Integration
from skyline_core.secrets_store import SecretNotFoundError, load_secret, tenant_redaction_key_id
from skyline_core.types import Sensitive
from skyline_worker.context import WorkerContext


class IntegrationUnavailableError(Exception):
    """The integration can't be used. ``reason`` is safe to show users."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class PreparedIntegration:
    integration: Integration
    spec: ConnectorSpec
    config: BaseModel
    credentials: BaseModel  # SecretStr fields; repr never shows them


async def load_integration(
    session: AsyncSession, *, tenant_id: UUID, integration_id: UUID
) -> Integration | None:
    return (
        await session.execute(
            select(Integration).where(
                Integration.tenant_id == tenant_id,
                Integration.id == integration_id,
                Integration.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()


async def prepare(
    session: AsyncSession, ctx: WorkerContext, integration: Integration
) -> PreparedIntegration:
    """Validate config, decrypt and parse credentials. Raises IntegrationUnavailableError."""
    try:
        spec = get_spec(integration.provider)
    except UnknownProviderError:
        raise IntegrationUnavailableError("this provider is not supported") from None
    try:
        config = spec.info.config_model.model_validate(integration.config)
    except ValidationError:
        raise IntegrationUnavailableError("the integration configuration is invalid") from None
    if integration.credential_secret_id is None:
        raise IntegrationUnavailableError("the integration has no credential")
    try:
        sealed: Sensitive[bytes] = await load_secret(
            session,
            ctx.opener,
            tenant_id=integration.tenant_id,
            secret_id=integration.credential_secret_id,
            purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
        )
        credentials = spec.credential_model.model_validate_json(sealed.reveal())
    except (SecretNotFoundError, CryptoError, ValidationError):
        raise IntegrationUnavailableError("the stored credential could not be read") from None
    return PreparedIntegration(integration, spec, config, credentials)


async def redaction_key(session: AsyncSession, ctx: WorkerContext, tenant_id: UUID) -> bytes:
    """The tenant's HMAC key for redaction markers. Raises IntegrationUnavailableError."""
    secret_id = await tenant_redaction_key_id(session, tenant_id=tenant_id)
    if secret_id is None:
        raise IntegrationUnavailableError("the tenant has no redaction key (run skyline-migrate)")
    try:
        key = await load_secret(
            session,
            ctx.opener,
            tenant_id=tenant_id,
            secret_id=secret_id,
            purpose=SecretPurpose.REDACTION_HMAC_KEY,
        )
    except (SecretNotFoundError, CryptoError):
        raise IntegrationUnavailableError("the tenant redaction key could not be read") from None
    return key.reveal()
