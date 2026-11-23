"""Envelope encryption: round trips, and every way a ciphertext can be misused must fail."""

from __future__ import annotations

import json
import os
import pickle
import secrets
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from skyline_core.crypto import (
    CryptoError,
    DecryptionError,
    EncryptionContext,
    KeyNotFoundError,
    LocalKeyProvider,
    SecretOpener,
    SecretPurpose,
    SecretSealer,
    create_kek_file,
)
from skyline_core.types import Sensitive


@pytest.fixture
def provider() -> LocalKeyProvider:
    return LocalKeyProvider({"k1": secrets.token_bytes(32)}, "k1")


def _ctx(purpose: SecretPurpose = SecretPurpose.INTEGRATION_CREDENTIAL) -> EncryptionContext:
    return EncryptionContext(tenant_id=uuid4(), secret_id=uuid4(), purpose=purpose)


async def test_round_trip(provider: LocalKeyProvider) -> None:
    ctx = _ctx()
    plaintext = secrets.token_bytes(48)
    sealed = await SecretSealer(provider).seal(plaintext, ctx)
    assert plaintext not in sealed.ciphertext
    assert len(sealed.nonce) == 12
    assert "ciphertext" not in repr(sealed)
    assert await SecretOpener(provider).open(sealed, ctx) == plaintext


async def test_nonces_and_deks_are_fresh(provider: LocalKeyProvider) -> None:
    ctx = _ctx()
    sealer = SecretSealer(provider)
    first = await sealer.seal(b"same", ctx)
    second = await sealer.seal(b"same", ctx)
    assert first.nonce != second.nonce
    assert first.wrapped_dek != second.wrapped_dek
    assert first.ciphertext != second.ciphertext


@pytest.mark.parametrize("field", ["tenant_id", "secret_id", "purpose"])
async def test_context_mismatch_fails(provider: LocalKeyProvider, field: str) -> None:
    ctx = _ctx()
    sealed = await SecretSealer(provider).seal(b"credential", ctx)
    other = {
        "tenant_id": uuid4(),
        "secret_id": uuid4(),
        "purpose": SecretPurpose.REDACTION_HMAC_KEY,
    }[field]
    with pytest.raises(DecryptionError):
        await SecretOpener(provider).open(sealed, replace(ctx, **{field: other}))


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "wrapped_dek"])
async def test_tampering_fails(provider: LocalKeyProvider, field: str) -> None:
    ctx = _ctx()
    sealed = await SecretSealer(provider).seal(b"credential", ctx)
    value = bytearray(getattr(sealed, field))
    value[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        await SecretOpener(provider).open(replace(sealed, **{field: bytes(value)}), ctx)


async def test_truncated_wrapped_key_fails(provider: LocalKeyProvider) -> None:
    ctx = _ctx()
    sealed = await SecretSealer(provider).seal(b"credential", ctx)
    with pytest.raises(DecryptionError):
        await SecretOpener(provider).open(replace(sealed, wrapped_dek=b"short"), ctx)


async def test_wrong_kek_or_provider_or_version_fails(provider: LocalKeyProvider) -> None:
    ctx = _ctx()
    sealed = await SecretSealer(provider).seal(b"credential", ctx)
    stranger = LocalKeyProvider({"k1": secrets.token_bytes(32)}, "k1")
    with pytest.raises(DecryptionError):
        await SecretOpener(stranger).open(sealed, ctx)
    with pytest.raises(KeyNotFoundError):
        await SecretOpener(provider).open(replace(sealed, key_id="k9"), ctx)
    with pytest.raises(DecryptionError):
        await SecretOpener(provider).open(replace(sealed, key_provider="aws-kms"), ctx)
    with pytest.raises(DecryptionError):
        await SecretOpener(provider).open(replace(sealed, format_version=2), ctx)
    with pytest.raises(DecryptionError):
        await SecretOpener(provider).open(replace(sealed, nonce=b"\x00" * 8), ctx)


async def test_rotation_keeps_old_keys_unwrapping() -> None:
    old = secrets.token_bytes(32)
    before = LocalKeyProvider({"k1": old}, "k1")
    ctx = _ctx()
    sealed = await SecretSealer(before).seal(b"credential", ctx)
    after = LocalKeyProvider({"k1": old, "k2": secrets.token_bytes(32)}, "k2")
    assert await SecretOpener(after).open(sealed, ctx) == b"credential"
    assert (await SecretSealer(after).seal(b"x", ctx)).key_id == "k2"


async def test_empty_or_huge_plaintext_rejected(provider: LocalKeyProvider) -> None:
    with pytest.raises(CryptoError):
        await SecretSealer(provider).seal(b"", _ctx())
    with pytest.raises(CryptoError):
        await SecretSealer(provider).seal(b"x" * (65 * 1024), _ctx())


def test_provider_validation() -> None:
    with pytest.raises(CryptoError):
        LocalKeyProvider({"k1": b"short"}, "k1")
    with pytest.raises(CryptoError):
        LocalKeyProvider({"k1": secrets.token_bytes(32)}, "k2")
    assert "***" in repr(LocalKeyProvider({"k1": secrets.token_bytes(32)}, "k1"))


async def test_kek_file_create_and_load(tmp_path: Path) -> None:
    path = tmp_path / "kek.json"
    key_id = create_kek_file(path)
    provider = LocalKeyProvider.from_file(path)
    assert provider.active_key_id == key_id
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o400
    with pytest.raises(FileExistsError):
        create_kek_file(path)
    ctx = _ctx()
    sealed = await SecretSealer(provider).seal(b"x", ctx)
    assert await SecretOpener(LocalKeyProvider.from_file(path)).open(sealed, ctx) == b"x"


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        json.dumps({"format": "other", "version": 1, "active": "a", "keys": {}}),
        json.dumps(
            {"format": "skyline-local-kek", "version": 1, "active": "a", "keys": {"a": "!!"}}
        ),
        json.dumps({"format": "skyline-local-kek", "version": 2, "active": "a", "keys": {}}),
    ],
)
def test_malformed_kek_files_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "kek.json"
    path.write_text(content, encoding="utf-8")
    if os.name == "posix":
        path.chmod(0o400)
    with pytest.raises(CryptoError):
        LocalKeyProvider.from_file(path)


def test_missing_kek_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(CryptoError, match="cannot be read"):
        LocalKeyProvider.from_file(tmp_path / "missing.json")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_world_readable_kek_file_rejected(tmp_path: Path) -> None:
    path = tmp_path / "kek.json"
    create_kek_file(path)
    path.chmod(0o644)
    with pytest.raises(CryptoError, match="permissions"):
        LocalKeyProvider.from_file(path)


def test_aad_is_unambiguous_and_versioned() -> None:
    ctx = _ctx()
    aad = ctx.aad()
    assert aad.startswith(b"skyline-aad-v1\x00")
    assert ctx.tenant_id.bytes in aad
    assert ctx.as_kms_context()["purpose"] == "integration_credential"


def test_sensitive_wrapper_never_prints_or_pickles() -> None:
    value = Sensitive(secrets.token_hex(8))
    assert value.reveal() not in repr(value)
    assert value.reveal() not in str(value)
    assert value.reveal() not in f"{value}"
    with pytest.raises(TypeError):
        pickle.dumps(value)
