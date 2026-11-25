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
    #: Accounts: after each consecutive failure the next attempt waits twice as long as the
    #: last (1 s, 2 s, 4 s … 256 s), up to ``login_lock_seconds``, a temporary lock that ends
    #: on its own. Refused attempts never extend a wait. This is Cyber Essentials v3.3's
    #: "throttling" option (no more than 10 guesses in 5 minutes; defaults allow 9). 0 turns
    #: the waits off, leaving only the ceiling below.
    login_first_wait_ms: int = Field(default=1000, ge=0, le=60_000)
    login_lock_seconds: int = Field(default=300, ge=1, le=3600)
    #: Minutes without a failed attempt after which an account's streak starts again.
    login_streak_reset_minutes: int = Field(default=60, ge=1, le=24 * 60)
    #: Hard ceiling per sliding window, whatever the waits: the bounds keep it within CE
    #: v3.3 (at most 10 failures in any 5 minutes per account or known device).
    login_account_failures: int = Field(default=10, ge=3, le=10)
    login_ip_failures: int = Field(default=100, ge=10, le=10_000)
    login_window_minutes: int = Field(default=5, ge=5, le=60)
    #: A successful sign-in marks the browser as a known device of that account (signed
    #: cookie). Its attempts get their own waits and ceiling, so an attacker holding the
    #: account's lock can't keep the real user's devices out. 400 days is browsers' cap.
    login_device_days: int = Field(default=90, ge=1, le=400)
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
    def _login_waits_are_consistent(self) -> ApiSettings:
        if self.login_first_wait_ms > self.login_lock_seconds * 1000:
            msg = "SKYLINE_LOGIN_FIRST_WAIT_MS must not exceed SKYLINE_LOGIN_LOCK_SECONDS"
            raise ValueError(msg)
        if self.login_streak_reset_minutes * 60 <= self.login_lock_seconds:
            msg = (
                "SKYLINE_LOGIN_STREAK_RESET_MINUTES must be longer than "
                "SKYLINE_LOGIN_LOCK_SECONDS, or a streak would be forgotten during its lock"
            )
            raise ValueError(msg)
        return self

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
