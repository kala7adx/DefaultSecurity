"""Opaque tokens, hashing and HMAC helpers (constant-time comparisons only)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Final

TOKEN_BYTES: Final = 32  # 256-bit session and registration tokens


def new_token(nbytes: int = TOKEN_BYTES) -> str:
    """A URL-safe random token with ``nbytes`` of entropy."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> bytes:
    """SHA-256 of a high-entropy token. Only this hash is stored, never the token."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def hmac_sha256(key: bytes, *parts: bytes) -> bytes:
    """HMAC-SHA256 over length-prefixed parts, so ``("ab", "c")`` != ``("a", "bc")``."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for part in parts:
        mac.update(len(part).to_bytes(4, "big"))
        mac.update(part)
    return mac.digest()


def b64url(data: bytes) -> str:
    """Unpadded base64url text."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def constant_time_equals(left: str | bytes, right: str | bytes) -> bool:
    """Compare two tokens without leaking timing information."""
    a = left.encode() if isinstance(left, str) else left
    b = right.encode() if isinstance(right, str) else right
    return hmac.compare_digest(a, b)
