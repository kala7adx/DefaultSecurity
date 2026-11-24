"""Negative tests for redaction: secrets must never survive into logs or stored config."""

from __future__ import annotations

import secrets
import time

import pytest

from skyline_core.redaction import (
    REDACTED,
    RedactionDepthError,
    RedactionRules,
    config_hash,
    contains_secret_pattern,
    redact_for_log,
    redact_raw_config,
)
from skyline_core.types import JSON

# Built at runtime so no secret-shaped literal sits in the repository.
FAKE_AWS_KEY_ID = "AKIA" + "Q" * 16
FAKE_JWT = "eyJ" + "a" * 10 + "." + "b" * 10 + "." + "c" * 10
FAKE_PEM = "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "db_password",
        "client_secret",
        "access_token",
        "Authorization",
        "cookie",
        "x-api-key",
        "private_key",
        "aws_credentials",
        "user_data",
        "set-cookie",
        "csrf",
    ],
)
def test_sensitive_keys_are_masked(key: str) -> None:
    value = secrets.token_hex(8)
    out = redact_for_log({key: value, "safe": "visible"})
    assert out == {key: REDACTED, "safe": "visible"}


@pytest.mark.parametrize(
    "value",
    [
        f"key id {FAKE_AWS_KEY_ID} leaked",
        f"Authorization: Bearer {secrets.token_urlsafe(16)}",
        f"token is {FAKE_JWT}",
        FAKE_PEM,
        f"password={secrets.token_hex(6)}&user=bob",
        f"postgresql://skyline:{secrets.token_hex(6)}@db:5432/skyline",
    ],
)
def test_secret_shaped_values_are_masked_anywhere(value: str) -> None:
    out = redact_for_log({"message": value, "nested": [{"note": value}]})
    assert isinstance(out, dict)
    assert REDACTED in str(out["message"])
    for fragment in (FAKE_AWS_KEY_ID, FAKE_JWT, "BEGIN " + "PRIVATE KEY"):
        assert fragment not in str(out)


def test_unknown_objects_are_repr_masked() -> None:
    class Leaky:
        def __repr__(self) -> str:
            return f"Leaky({FAKE_AWS_KEY_ID})"

    assert FAKE_AWS_KEY_ID not in str(redact_for_log(Leaky()))
    assert redact_for_log(b"\x00\x01") == "<2 bytes>"
    assert redact_for_log((1, None, True)) == [1, None, True]


def test_deep_structures_are_cut_off() -> None:
    deep: JSON = "x"
    for _ in range(40):
        deep = {"a": deep}
    assert REDACTED in str(redact_for_log(deep))


def test_raw_config_redaction_replaces_values_with_hmac() -> None:
    key = secrets.token_bytes(32)
    user_data = f"#!/bin/sh\nexport DB_PASSWORD={secrets.token_hex(8)}"
    config: JSON = {
        "name": "vm-1",
        "UserData": user_data,
        "Environment": {"Variables": {"API_KEY": secrets.token_hex(8)}},
        "notes": f"rotated {FAKE_AWS_KEY_ID}",
        "volumes": [{"size": 8}],
        "empty_secret": None,
    }
    rules = RedactionRules.for_keys(["Environment"])
    out = redact_raw_config(config, rules=rules, hmac_key=key)
    assert isinstance(out, dict)
    assert out["name"] == "vm-1"
    assert out["volumes"] == [{"size": 8}]
    assert out["empty_secret"] is None
    for field in ("UserData", "Environment"):
        marker = out[field]
        assert isinstance(marker, dict)
        assert marker["redacted"] is True
        assert isinstance(marker["hmac"], str)
        assert len(marker["hmac"]) == 64
    assert str(out["notes"]).startswith("rotated [REDACTED:")
    assert user_data not in str(out)
    assert FAKE_AWS_KEY_ID not in str(out)


def test_raw_config_hmac_detects_change_but_depends_on_tenant_key() -> None:
    config_a: JSON = {"user_data": "one"}
    config_b: JSON = {"user_data": "two"}
    rules = RedactionRules()
    key_1, key_2 = secrets.token_bytes(32), secrets.token_bytes(32)
    a1 = redact_raw_config(config_a, rules=rules, hmac_key=key_1)
    b1 = redact_raw_config(config_b, rules=rules, hmac_key=key_1)
    a2 = redact_raw_config(config_a, rules=rules, hmac_key=key_2)
    assert a1 != b1  # a change is visible
    assert a1 != a2  # the same value under another tenant's key looks different
    assert config_hash(a1) != config_hash(b1)


def test_raw_config_depth_limit() -> None:
    deep: JSON = 1
    for _ in range(40):
        deep = [deep]
    with pytest.raises(RedactionDepthError):
        redact_raw_config(deep, rules=RedactionRules(), hmac_key=b"k" * 32)


def test_contains_secret_pattern() -> None:
    assert contains_secret_pattern(FAKE_JWT)
    assert not contains_secret_pattern("t3.micro in eu-west-2")


@pytest.mark.parametrize(
    "template",
    [
        "DB_PASSWORD={v}",
        "client_secret={v}&grant_type=client_credentials",
        "https://login.example.com/token?access_token={v}",
        "refresh_token: {v}",
        '{{"password": "{v}"}}',
        "{{'api_key': '{v}'}}",
        "DefaultEndpointsProtocol=https;AccountName=x;AccountKey={v};",
        "https://x.blob.core.windows.net/c?sv=2024&sig={v}&se=2026",
        "PRIVATE_KEY={v}",
    ],
)
def test_common_secret_layouts_are_masked(template: str) -> None:
    value = secrets.token_urlsafe(18).replace("-", "a").replace("_", "b")
    out = str(redact_for_log(template.format(v=value)))
    assert value not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "token",
    [
        "ghp_" + "a1" * 18,
        "github_pat_" + "b2" * 20,
        "xoxb-" + "1234567890-abcdef",
        "sk_live_" + "c3" * 10,
        "AIza" + "d" * 35,
        "Basic " + "dXNlcjpwYXNzd29yZA==",
    ],
)
def test_vendor_token_formats_are_masked(token: str) -> None:
    assert token not in str(redact_for_log(f"value is {token} here"))


def test_harmless_text_is_left_alone() -> None:
    for text in ("password reset failed for user", "design=compact", "t3.micro in eu-west-2"):
        assert redact_for_log(text) == text


@pytest.mark.parametrize(
    "key",
    ["DB_PASSWORD", "dbPassword", "clientSecret", "X-Api-Key", "env", "Environment", "key", "SIG"],
)
def test_log_keys_are_normalised(key: str) -> None:
    assert redact_for_log({key: "v"}) == {key: REDACTED}


@pytest.mark.parametrize(
    "key",
    [
        "Environment",
        "environment",
        "ClientSecret",
        "PrivateKey",
        "connectionStrings",
        "UserData",
        "client-secret",
        "SasToken",
        "env",
    ],
)
def test_raw_config_keys_are_normalised(key: str) -> None:
    out = redact_raw_config(
        {key: "v", "Key": "env", "Value": "prod"}, rules=RedactionRules(), hmac_key=b"k" * 32
    )
    assert isinstance(out, dict)
    marker = out[key]
    assert isinstance(marker, dict)
    assert marker["redacted"] is True
    # AWS tag lists ({"Key": ..., "Value": ...}) are not secrets.
    assert out["Key"] == "env"
    assert out["Value"] == "prod"


@pytest.mark.parametrize(
    "key",
    [
        "HttpTokens",
        "PasswordPolicy",
        "PasswordLastUsed",
        "password_enabled",
        "AccessKeyMetadata",
        "passwordCredentials",
        "SecretArn",
        "EnvironmentName",
        "TokenEndpoint",
    ],
)
def test_check_relevant_fields_survive_raw_config_redaction(key: str) -> None:
    config: JSON = {key: {"MinimumPasswordLength": 14} if key == "PasswordPolicy" else "required"}
    assert redact_raw_config(config, rules=RedactionRules(), hmac_key=b"k" * 32) == config


@pytest.mark.parametrize(
    "text",
    [
        "a_" * 50_000,
        "a." * 50_000,
        "password" * 12_000,
        'password="' * 10_000,
        "-----BEGIN " * 9_000,
        "x://" + "a:" * 40_000,
    ],
)
def test_redaction_is_linear_time(text: str) -> None:
    started = time.perf_counter()
    redact_for_log(text)
    redact_raw_config({"description": text}, rules=RedactionRules(), hmac_key=b"k" * 32)
    contains_secret_pattern(text[:32_000])
    # Quadratic behaviour took ~100 s on 80 KB; linear is milliseconds. 2 s avoids CI flakes.
    assert time.perf_counter() - started < 2.0


def test_quoted_and_escaped_values_are_fully_masked() -> None:
    for text in (
        '"password": "hunter 22"',
        '{\\"password\\": \\"hunter 22\\"}',
        "secret='hunter 22'",
    ):
        out = str(redact_for_log(text))
        assert "hunter" not in out and "22" not in out, out


def test_long_strings_are_truncated_in_logs_and_marked_in_config() -> None:
    long_text = "x" * 20_000
    assert len(str(redact_for_log(long_text))) < 9_000
    marker = redact_raw_config({"blob": "y" * 40_000}, rules=RedactionRules(), hmac_key=b"k" * 32)
    assert isinstance(marker, dict)
    blob = marker["blob"]
    assert isinstance(blob, dict)
    assert blob["redacted"] is True


SECRET_ARN = "arn:aws:secretsmanager:eu-west-2:123456789012:secret:prod-db-AbCdEf"


def test_policies_mentioning_secret_arns_survive() -> None:
    policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",'
        f'"Action":"secretsmanager:GetSecretValue","Resource":"{SECRET_ARN}"}}]}}'
    )
    config: JSON = {"ResourcePolicy": policy, "Policy": f"arn:aws:s3:::b/{SECRET_ARN}"}
    assert redact_raw_config(config, rules=RedactionRules(), hmac_key=b"k" * 32) == config
    assert redact_for_log(SECRET_ARN) == SECRET_ARN


def test_only_secret_spans_are_masked_in_config_strings() -> None:
    key = b"k" * 32
    text = f"connect with password={secrets.token_hex(6)} to db1 ({FAKE_AWS_KEY_ID})"
    out = redact_raw_config({"notes": text}, rules=RedactionRules(), hmac_key=key)
    assert isinstance(out, dict)
    notes = str(out["notes"])
    assert notes.startswith("connect with password=[REDACTED:")
    assert "to db1" in notes
    assert FAKE_AWS_KEY_ID not in notes
    # The same secret under the same tenant key gives the same tag (change detection).
    assert out == redact_raw_config({"notes": text}, rules=RedactionRules(), hmac_key=key)
