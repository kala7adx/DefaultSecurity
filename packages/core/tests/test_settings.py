from __future__ import annotations

import secrets
import ssl
from pathlib import Path

import pytest
from pydantic import ValidationError

from skyline_core.settings import CoreSettings, SettingsError, validate_origin


def test_secret_is_read_from_file_and_stripped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = secrets.token_hex(8)
    secret_file = tmp_path / "db_password"
    secret_file.write_text(value + "\n", encoding="utf-8")
    monkeypatch.setenv("SKYLINE_DB_PASSWORD_FILE", str(secret_file))
    settings = CoreSettings()
    assert settings.db_password is not None
    assert settings.db_password.get_secret_value() == value
    assert value not in repr(settings)


@pytest.mark.parametrize(
    "name", ["SKYLINE_DB_PASSWORD", "skyline_db_password", "Skyline_Db_Password"]
)
def test_secret_in_plain_env_var_is_rejected(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, secrets.token_hex(8))
    with pytest.raises(SettingsError, match="SKYLINE_DB_PASSWORD_FILE"):
        CoreSettings()


def test_missing_secret_file_error_does_not_leak_path_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SKYLINE_DB_PASSWORD_FILE", str(tmp_path / "missing"))
    with pytest.raises(SettingsError, match="cannot be read"):
        CoreSettings()


def test_oversized_secret_file_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    big = tmp_path / "big"
    big.write_bytes(b"x" * (65 * 1024))
    monkeypatch.setenv("SKYLINE_DB_PASSWORD_FILE", str(big))
    with pytest.raises(SettingsError, match="larger"):
        CoreSettings()


def test_unknown_settings_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        CoreSettings(not_a_setting=1)  # type: ignore[call-arg]


@pytest.mark.parametrize("user", ["skyline_api; DROP", "a b", "x" * 64])
def test_db_user_must_be_identifier(user: str) -> None:
    with pytest.raises(ValidationError):
        CoreSettings(db_user=user)


def test_production_defaults_to_full_tls_verification() -> None:
    settings = CoreSettings()
    context = settings.db_ssl()
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_sslmode_variants() -> None:
    assert CoreSettings(db_sslmode="disable").db_ssl() is False
    require = CoreSettings(db_sslmode="require").db_ssl()
    assert isinstance(require, ssl.SSLContext)
    assert require.verify_mode == ssl.CERT_NONE
    verify_ca = CoreSettings(db_sslmode="verify-ca").db_ssl()
    assert isinstance(verify_ca, ssl.SSLContext)
    assert verify_ca.check_hostname is False
    assert verify_ca.verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://localhost:3000", "http://localhost:3000"),
        ("https://skyline.example.com/", "https://skyline.example.com"),
    ],
)
def test_validate_origin_accepts(value: str, expected: str) -> None:
    assert validate_origin(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "https://example.com/path",
        "https://user:pw@example.com",
        "https://example.com?x=1",
        "javascript:alert(1)",
        "",
    ],
)
def test_validate_origin_rejects(value: str) -> None:
    with pytest.raises(ValueError, match="origin"):
        validate_origin(value)


def test_empty_plain_secret_env_var_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKYLINE_DB_PASSWORD", "")
    with pytest.raises(SettingsError):
        CoreSettings()
