from __future__ import annotations

import secrets

import pytest

from skyline_core.security.passwords import (
    MAX_LENGTH,
    PasswordPolicyError,
    PasswordPolicyViolation,
    check_password_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from skyline_core.security.tokens import (
    b64url,
    constant_time_equals,
    hash_token,
    hmac_sha256,
    new_token,
)


@pytest.mark.parametrize(
    ("candidate", "violation"),
    [
        ("short", PasswordPolicyViolation.TOO_SHORT),
        ("x" * (MAX_LENGTH + 1), PasswordPolicyViolation.TOO_LONG),
        ("Password1234", PasswordPolicyViolation.COMMON),
        ("Welcome2026!!", PasswordPolicyViolation.COMMON),
        ("qwertyuiop12", PasswordPolicyViolation.COMMON),
        ("123456789012", PasswordPolicyViolation.COMMON),
        ("210987654321", PasswordPolicyViolation.COMMON),
        ("aaaaaaaaaaaaaa", PasswordPolicyViolation.REPEATED),
        ("abababababababab", PasswordPolicyViolation.REPEATED),
    ],
)
def test_policy_rejects(candidate: str, violation: PasswordPolicyViolation) -> None:
    with pytest.raises(PasswordPolicyError) as info:
        check_password_policy(candidate)
    assert info.value.violation is violation


def test_policy_rejects_email_in_password() -> None:
    with pytest.raises(PasswordPolicyError) as info:
        check_password_policy("my-alice.smith-river-9", email="alice.smith@example.com")
    assert info.value.violation is PasswordPolicyViolation.CONTAINS_EMAIL


@pytest.mark.parametrize(
    "candidate",
    [
        "correct horse battery staple",
        "river-lamp-orbit-71",
        "Ünïcødé passphrase ok",
        "x" * 5 + "yz" * 4,
    ],
)
def test_policy_accepts_long_passphrases(candidate: str) -> None:
    check_password_policy(candidate, email="bob@example.com")


def test_policy_has_no_practical_maximum() -> None:
    check_password_policy(secrets.token_urlsafe(700)[:MAX_LENGTH])


def test_hash_and_verify() -> None:
    password = secrets.token_urlsafe(16)
    hashed = hash_password(password)
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, password)
    assert not verify_password(hashed, password + "x")
    assert not needs_rehash(hashed)


def test_verify_unknown_user_and_garbage_hash() -> None:
    assert not verify_password(None, secrets.token_urlsafe(16))
    assert not verify_password("not-a-hash", "whatever-password")
    assert not verify_password(hash_password("p" * 12 + "q"), "x" * (MAX_LENGTH + 1))


def test_hash_refuses_over_length() -> None:
    with pytest.raises(PasswordPolicyError):
        hash_password("x" * (MAX_LENGTH + 1))


def test_tokens() -> None:
    token = new_token()
    assert len(token) >= 43
    assert new_token() != token
    assert len(hash_token(token)) == 32
    assert hash_token(token) == hash_token(token)
    assert constant_time_equals(token, token)
    assert not constant_time_equals(token, token[:-1] + "A")
    assert constant_time_equals(b"a", "a")


def test_hmac_parts_are_length_prefixed() -> None:
    key = secrets.token_bytes(32)
    assert hmac_sha256(key, b"ab", b"c") != hmac_sha256(key, b"a", b"bc")
    assert b64url(b"\xff\xff") == "__8"
