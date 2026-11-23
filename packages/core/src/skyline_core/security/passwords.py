"""Password hashing (argon2id) and the password policy (ARCHITECTURE §9, ADR-0008).

Policy, aligned with Cyber Essentials v3.3 password-based authentication guidance:
minimum 12 characters, no practical maximum (1,024 characters is a DoS guard for hashing
only), no composition rules, and a deny-list of common passwords and password bases.
"""

from __future__ import annotations

import secrets
from enum import StrEnum
from functools import cache
from importlib import resources
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH: Final = 12
MAX_LENGTH: Final = 1024

# Keyboard and digit runs ("123456789012", "qwertyuiopas") and their reverses.
_RUNS: Final = ("01234567890123456789", "qwertyuiopasdfghjklzxcvbnm", "abcdefghijklmnopqrstuvwxyz")
_SEQUENCES: Final = _RUNS + tuple(run[::-1] for run in _RUNS)

# argon2-cffi defaults follow RFC 9106's second recommended profile (argon2id, t=3, 64 MiB, p=4).
_hasher: Final = PasswordHasher()


class PasswordPolicyViolation(StrEnum):
    """Why a new password was rejected. Codes are shown to the user; they reveal nothing."""

    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    COMMON = "common"
    CONTAINS_EMAIL = "contains_email"
    REPEATED = "repeated_characters"


class PasswordPolicyError(ValueError):
    """The candidate password breaks the policy."""

    def __init__(self, violation: PasswordPolicyViolation) -> None:
        super().__init__(violation.value)
        self.violation = violation


@cache
def _blocklist() -> frozenset[str]:
    text = (
        resources.files("skyline_core.security")
        .joinpath("common_passwords.txt")
        .read_text(encoding="utf-8")
    )
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


# A real argon2id hash of a random value, computed at import so that even the first login
# for an unknown user costs the same as one for a real user (no timing oracle after restart).
_DUMMY_HASH: Final = _hasher.hash(secrets.token_urlsafe(32))


def check_password_policy(candidate: str, *, email: str | None = None) -> None:
    """Raise :class:`PasswordPolicyError` if ``candidate`` is not acceptable."""
    if len(candidate) < MIN_LENGTH:
        raise PasswordPolicyError(PasswordPolicyViolation.TOO_SHORT)
    if len(candidate) > MAX_LENGTH:
        raise PasswordPolicyError(PasswordPolicyViolation.TOO_LONG)
    lowered = candidate.lower()
    letters_only = "".join(ch for ch in lowered if ch.isalpha())
    blocklist = _blocklist()
    if lowered in blocklist or (letters_only and letters_only in blocklist):
        raise PasswordPolicyError(PasswordPolicyViolation.COMMON)
    if any(lowered in seq for seq in _SEQUENCES):
        raise PasswordPolicyError(PasswordPolicyViolation.COMMON)
    if len(set(lowered)) <= 2:  # noqa: PLR2004 - "aaaaaaaaaaaa", "abababababab"
        raise PasswordPolicyError(PasswordPolicyViolation.REPEATED)
    if email:
        local_part = email.split("@", 1)[0].lower()
        if len(local_part) >= 4 and local_part in lowered:  # noqa: PLR2004
            raise PasswordPolicyError(PasswordPolicyViolation.CONTAINS_EMAIL)


def hash_password(password: str) -> str:
    """Hash a password with argon2id. Call :func:`check_password_policy` first."""
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(PasswordPolicyViolation.TOO_LONG)
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Constant-work verification. ``stored_hash=None`` (unknown user) still runs argon2."""
    if len(password) > MAX_LENGTH:
        return False
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if the hash was made with weaker parameters than the current defaults."""
    return _hasher.check_needs_rehash(stored_hash)
