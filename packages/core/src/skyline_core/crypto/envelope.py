"""Seal and open secrets with AES-256-GCM using a fresh DEK and nonce per secret."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from skyline_core.crypto.context import EncryptionContext
from skyline_core.crypto.errors import CryptoError, DecryptionError
from skyline_core.crypto.keyprovider import DataKeyGenerator, DataKeyUnwrapper

FORMAT_VERSION: Final = 1
_NONCE_BYTES: Final = 12
_MAX_PLAINTEXT_BYTES: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class SealedSecret:
    """What gets stored in the ``secrets`` table. None of it is sensitive on its own."""

    key_provider: str
    key_id: str
    wrapped_dek: bytes
    nonce: bytes
    ciphertext: bytes
    format_version: int = FORMAT_VERSION

    def __repr__(self) -> str:
        return f"SealedSecret(key_provider={self.key_provider!r}, key_id={self.key_id!r})"


class SecretSealer:
    """Encrypt-only side (API, migrate). Never able to decrypt what it seals."""

    def __init__(self, generator: DataKeyGenerator) -> None:
        self._generator = generator

    async def seal(self, plaintext: bytes, ctx: EncryptionContext) -> SealedSecret:
        if not plaintext or len(plaintext) > _MAX_PLAINTEXT_BYTES:
            msg = "secret is empty or too large"
            raise CryptoError(msg)
        data_key = await self._generator.generate_data_key(ctx)
        try:
            nonce = secrets.token_bytes(_NONCE_BYTES)
            ciphertext = AESGCM(bytes(data_key.plaintext)).encrypt(nonce, plaintext, ctx.aad())
        finally:
            data_key.wipe()
        return SealedSecret(
            key_provider=self._generator.name,
            key_id=data_key.key_id,
            wrapped_dek=data_key.wrapped,
            nonce=nonce,
            ciphertext=ciphertext,
        )


class SecretOpener:
    """Decrypt-only side (worker). Plaintext lives in memory for one job only."""

    def __init__(self, unwrapper: DataKeyUnwrapper) -> None:
        self._unwrapper = unwrapper

    async def open(self, sealed: SealedSecret, ctx: EncryptionContext) -> bytes:
        if sealed.format_version != FORMAT_VERSION or sealed.key_provider != self._unwrapper.name:
            raise DecryptionError
        if len(sealed.nonce) != _NONCE_BYTES:
            raise DecryptionError
        dek = await self._unwrapper.unwrap(sealed.wrapped_dek, sealed.key_id, ctx)
        try:
            return AESGCM(bytes(dek)).decrypt(sealed.nonce, sealed.ciphertext, ctx.aad())
        except InvalidTag as exc:
            raise DecryptionError from exc
        finally:
            for i in range(len(dek)):
                dek[i] = 0
