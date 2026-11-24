"""API settings (environment variables prefixed ``SKYLINE_``)."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field, SecretStr, field_validator, model_validator

from skyline_core.settings import CoreSettings, Environment, validate_origin


class ApiSettings(CoreSettings):
    """Settings for ``skyline-api`` (DB role ``skyline_api``)."""

    secret_fields: ClassVar[frozenset[str]] = frozenset({"db_password", "session_key"})

    db_user: str = "skyline_api"
    #: The browser-facing origin. Unsafe requests must carry exactly this Origin header.
    public_origin: str = "http://localhost:3000"
    #: HMAC key for CSRF tokens and throttling subjects (>= 32 bytes, from a file).
    session_key: SecretStr | None = None
    session_idle_minutes: int = Field(default=30, ge=5, le=24 * 60)
    session_absolute_hours: int = Field(default=12, ge=1, le=12)  # DB CHECK caps at 12h
    #: Number of proxies in front of the API that *append* the client address to
    #: X-Forwarded-For. The Next.js web server passes the header through without appending,
    #: so it doesn't count: 1 behind a load balancer or edge proxy that appends (ALB, Caddy,
    #: ingress-nginx), 0 with nothing in front. Must be set explicitly in production; a
    #: wrong value either merges users into one IP bucket or trusts spoofed addresses. The
    #: API and web must only be reachable through that edge (network policy / security group).
    trusted_proxy_hops: int | None = Field(default=None, ge=0, le=3)
    max_body_bytes: int = Field(default=64 * 1024, ge=1024, le=1024 * 1024)
    login_account_failures: int = Field(default=10, ge=3, le=100)  # CE v3.3: <= 10 per 5 min
    login_ip_failures: int = Field(default=100, ge=10, le=10_000)
    login_window_minutes: int = Field(default=5, ge=1, le=60)
    #: Concurrent password hashes (argon2 uses 64 MiB each); more get 503 + Retry-After.
    max_concurrent_hashes: int = Field(default=8, ge=1, le=64)
    max_concurrent_hashes_per_ip: int = Field(default=2, ge=1, le=64)
    #: Uvicorn's cap on concurrent connections; beyond it new requests get 503.
    max_concurrency: int = Field(default=200, ge=10, le=10_000)
    #: HSTS. Unset means on in production and off elsewhere.
    hsts: bool | None = None
    port: int = Field(default=8000, ge=1, le=65535)

    @field_validator("public_origin")
    @classmethod
    def _origin(cls, value: str) -> str:
        return validate_origin(value)

    @model_validator(mode="after")
    def _production_requires_explicit_proxy_hops(self) -> ApiSettings:
        if self.env is Environment.PRODUCTION and self.trusted_proxy_hops is None:
            msg = (
                "SKYLINE_TRUSTED_PROXY_HOPS must be set in production: the number of proxies "
                "that append to X-Forwarded-For (1 behind a load balancer, 0 with none; the "
                "web server doesn't count)"
            )
            raise ValueError(msg)
        return self

    @property
    def proxy_hops(self) -> int:
        return self.trusted_proxy_hops or 0

    @property
    def hsts_enabled(self) -> bool:
        return self.env is Environment.PRODUCTION if self.hsts is None else self.hsts

    @property
    def secure_cookies(self) -> bool:
        """``__Host-`` cookies need Secure; browsers accept it on http://localhost too."""
        return True
