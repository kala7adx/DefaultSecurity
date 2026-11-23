"""Encryption context: binds every ciphertext to its tenant, secret ID and purpose."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from uuid import UUID

_AAD_PREFIX: Final = b"skyline-aad-v1\x00"


class SecretPurpose(StrEnum):
    """What a stored secret is for. Part of the AAD, so a secret can't be reused elsewhere."""

    INTEGRATION_CREDENTIAL = "integration_credential"
    REDACTION_HMAC_KEY = "redaction_hmac_key"


@dataclass(frozen=True, slots=True)
class EncryptionContext:
    """Identifies one secret. Used as AES-GCM associated data and as KMS encryption context."""

    tenant_id: UUID
    secret_id: UUID
    purpose: SecretPurpose

    def aad(self) -> bytes:
        """Canonical, versioned, unambiguous encoding (fixed-length UUIDs, then the purpose)."""
        return (
            _AAD_PREFIX + self.tenant_id.bytes + self.secret_id.bytes + self.purpose.value.encode()
        )

    def as_kms_context(self) -> dict[str, str]:
        """Encryption-context map for cloud KMS providers (Phase 4); usable in key policies."""
        return {
            "tenant_id": str(self.tenant_id),
            "secret_id": str(self.secret_id),
            "purpose": self.purpose.value,
        }
