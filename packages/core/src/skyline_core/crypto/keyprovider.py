"""KeyProvider protocols: wrap and unwrap per-secret data keys (DEKs)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from skyline_core.crypto.context import EncryptionContext


@dataclass(slots=True)
class DataKey:
    """A fresh DEK: plaintext for immediate use, wrapped form for storage."""

    plaintext: bytearray
    wrapped: bytes
    key_id: str

    def wipe(self) -> None:
        """Overwrite the plaintext key (best effort; Python may hold other copies)."""
        for i in range(len(self.plaintext)):
            self.plaintext[i] = 0

    def __repr__(self) -> str:
        return f"DataKey(key_id={self.key_id!r}, plaintext=***)"


class DataKeyGenerator(Protocol):
    """Encrypt-side capability. The API identity only ever gets this one."""

    @property
    def name(self) -> str:
        """Provider name stored with each secret, e.g. ``local`` or ``aws-kms``."""
        ...

    async def generate_data_key(self, ctx: EncryptionContext) -> DataKey:
        """Return a new 256-bit DEK and its wrapped form, bound to ``ctx``."""
        ...


class DataKeyUnwrapper(Protocol):
    """Decrypt-side capability. Only the worker identity gets this one."""

    @property
    def name(self) -> str:
        """Provider name stored with each secret, e.g. ``local`` or ``aws-kms``."""
        ...

    async def unwrap(self, wrapped: bytes, key_id: str, ctx: EncryptionContext) -> bytearray:
        """Return the plaintext DEK, or raise ``DecryptionError`` if ``ctx`` doesn't match."""
        ...


class KeyProvider(DataKeyGenerator, DataKeyUnwrapper, Protocol):
    """A provider offering both capabilities (local KEK file, or a KMS used by migrate)."""
