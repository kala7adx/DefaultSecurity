"""Runtime configuration shared by every Skyline process (12-factor, ADR-0002).

Settings come from environment variables prefixed ``SKYLINE_``. **Secrets never come from plain
environment variables.** They are read from the file named by ``SKYLINE_<NAME>_FILE``, so they
don't leak through ``docker inspect``, process listings or crash reports. Setting a secret
directly (for example ``SKYLINE_DB_PASSWORD``) is rejected at start-up.
"""

from __future__ import annotations

import os
import ssl
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "SKYLINE_"
_MAX_SECRET_FILE_BYTES = 64 * 1024
_MAX_IDENTIFIER_LENGTH = 63  # PostgreSQL NAMEDATALEN - 1


class Environment(StrEnum):
    """Deployment environment. Development-only conveniences are keyed off this."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class SettingsError(RuntimeError):
    """Configuration is missing or unsafe. The message never contains secret values."""


class _FileSecretsSource(PydanticBaseSettingsSource):
    """Reads ``SKYLINE_<FIELD>_FILE`` for the fields a settings class lists as secrets."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        del field  # unused; the file path is derived from the field name only
        path_value = os.environ.get(f"{ENV_PREFIX}{field_name.upper()}_FILE")
        if not path_value:
            return None, field_name, False
        path = Path(path_value)
        try:
            size = path.stat().st_size
        except OSError as exc:
            msg = f"{ENV_PREFIX}{field_name.upper()}_FILE points to a file that cannot be read"
            raise SettingsError(msg) from exc
        if size > _MAX_SECRET_FILE_BYTES:
            msg = f"{ENV_PREFIX}{field_name.upper()}_FILE is larger than expected"
            raise SettingsError(msg)
        # Strip the trailing newline that editors and `echo` add.
        return path.read_text(encoding="utf-8").strip(), field_name, False

    def __call__(self) -> dict[str, Any]:
        secret_fields: frozenset[str] = getattr(self.settings_cls, "secret_fields", frozenset())
        values: dict[str, Any] = {}
        # Environment names are matched case-insensitively, as pydantic-settings does.
        plain = {key.upper() for key in os.environ}  # present at all, even if empty
        for name in secret_fields:
            if f"{ENV_PREFIX}{name.upper()}" in plain:
                msg = (
                    f"{ENV_PREFIX}{name.upper()} must not be set directly; "
                    f"use {ENV_PREFIX}{name.upper()}_FILE"
                )
                raise SettingsError(msg)
            value, key, _ = self.get_field_value(self.settings_cls.model_fields[name], name)
            if value is not None:
                values[key] = value
        return values


class CoreSettings(BaseSettings):
    """Settings every process needs: environment, logging, database and key provider."""

    model_config = SettingsConfigDict(env_prefix=ENV_PREFIX, extra="forbid", frozen=True)

    #: Field names that may only be supplied through ``*_FILE`` variables.
    secret_fields: ClassVar[frozenset[str]] = frozenset({"db_password"})

    env: Environment = Environment.PRODUCTION
    log_level: Literal["debug", "info", "warning", "error"] = "info"

    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "skyline"
    db_user: str = "skyline_api"
    db_password: SecretStr | None = None
    # Production default is full verification. Compose sets "disable" for its private network.
    db_sslmode: Literal["disable", "require", "verify-ca", "verify-full"] = "verify-full"
    db_sslrootcert: Path | None = None
    db_pool_size: int = Field(default=5, ge=1, le=50)
    db_statement_timeout_ms: int = Field(default=30_000, ge=1_000, le=600_000)

    key_provider: Literal["local"] = "local"
    local_kek_file: Path | None = None

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Init kwargs, then ``*_FILE`` secrets, then environment. No ``.env`` files."""
        del dotenv_settings, file_secret_settings
        return (init_settings, _FileSecretsSource(settings_cls), env_settings)

    @field_validator("db_user")
    @classmethod
    def _db_user_is_identifier(cls, value: str) -> str:
        if not value.replace("_", "").isalnum() or len(value) > _MAX_IDENTIFIER_LENGTH:
            msg = "db_user must be a plain PostgreSQL identifier"
            raise ValueError(msg)
        return value

    @property
    def is_development(self) -> bool:
        """True only for local development (enables OpenAPI docs and dev conveniences)."""
        return self.env is Environment.DEVELOPMENT

    def db_ssl(self) -> ssl.SSLContext | bool:
        """The ``ssl`` argument for asyncpg, built from ``db_sslmode``."""
        if self.db_sslmode == "disable":
            return False
        cafile = str(self.db_sslrootcert) if self.db_sslrootcert else None
        context = ssl.create_default_context(cafile=cafile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.db_sslmode == "require":
            # Encrypts but does not authenticate the server; only for networks you trust.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif self.db_sslmode == "verify-ca":
            context.check_hostname = False
        return context


def validate_origin(value: str) -> str:
    """Return a normalised ``scheme://host[:port]`` origin, or raise ``ValueError``."""
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        msg = "origin must be an http(s) URL"
        raise ValueError(msg)
    if parts.path not in {"", "/"} or parts.query or parts.fragment or parts.username:
        msg = "origin must not contain a path, query, fragment or credentials"
        raise ValueError(msg)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname}{port}"
