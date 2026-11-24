"""Opaque server-side sessions, CSRF tokens and the authorisation dependency (ADR-0008).

* Session cookie ``__Host-skyline_session``: 256-bit random token, HttpOnly, Secure,
  SameSite=Lax, Path=/. Only its SHA-256 is stored. Idle and absolute timeouts are enforced
  in SQL by ``skyline.resolve_session``.
* CSRF: double-submit. ``__Host-skyline_csrf`` (readable by JS) must equal the
  ``X-CSRF-Token`` header, and both must equal HMAC(session key, session ID).
* Every route depends on :func:`require` with a :class:`Permission` (tested), except the
  explicit public set.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final
from uuid import UUID, uuid4

from fastapi import Depends, Request, Response
from sqlalchemy import func, insert, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_api.errors import ApiError
from skyline_api.middleware import SAFE_METHODS
from skyline_api.rbac import Permission, permissions_for
from skyline_api.services import Services
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import ActorType, AuditOutcome, Session
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.logging import get_logger
from skyline_core.security.tokens import (
    b64url,
    constant_time_equals,
    hash_token,
    hmac_sha256,
    new_token,
)

SESSION_COOKIE: Final = "__Host-skyline_session"
CSRF_COOKIE: Final = "__Host-skyline_csrf"
CSRF_HEADER: Final = "x-csrf-token"
_MAX_TOKEN_CHARS: Final = 128
_TOUCH_AFTER: Final = timedelta(seconds=60)

#: Marker read by the route-permission test.
PERMISSION_ATTR: Final = "__skyline_permission__"

_log = get_logger(__name__)


def services(request: Request) -> Services:
    svc: Services = request.app.state.services
    return svc


ServicesDep = Annotated[Services, Depends(services)]


def ip_bucket(ip: str | None) -> str:
    """The per-IP throttling bucket: IPv6 clients share their /64 (one host usually holds a
    whole /64), IPv4-mapped addresses count as IPv4, and an unknown address shares one
    fixed bucket instead of skipping the check."""
    if ip is None:
        return "unknown"
    address = ipaddress.ip_address(ip)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


def client_ip(request: Request, svc: Services) -> str | None:
    """The client address, trusting X-Forwarded-For only for the configured proxy hops."""
    hops = svc.settings.proxy_hops
    candidate = request.client.host if request.client else None
    if hops:
        forwarded = [
            p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()
        ]
        if len(forwarded) < hops:
            # Not via the configured edge (or misconfigured): don't fall back to the peer,
            # which would put every such request in the proxy's bucket.
            _log.warning("x_forwarded_for_too_short", expected_hops=hops, got=len(forwarded))
            return None
        candidate = forwarded[-hops]
    try:
        return str(ipaddress.ip_address(candidate)) if candidate else None
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    tenant_id: UUID
    role: str
    session_id: UUID
    token_hash: bytes
    must_change_password: bool
    ip: str | None

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.role)


def csrf_token(svc: Services, session_id: UUID) -> str:
    return b64url(hmac_sha256(svc.session_key.reveal(), b"csrf", session_id.bytes))


def set_session_cookies(response: Response, svc: Services, token: str, session_id: UUID) -> None:
    max_age = svc.settings.session_absolute_hours * 3600
    response.set_cookie(
        SESSION_COOKIE, token, max_age=max_age, path="/", secure=True, httponly=True, samesite="lax"
    )
    # Not HttpOnly: the web app reads it and echoes it in X-CSRF-Token.
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token(svc, session_id),
        max_age=max_age,
        path="/",
        secure=True,
        httponly=False,
        samesite="lax",
    )


def clear_session_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(
            name, path="/", secure=True, httponly=name == SESSION_COOKIE, samesite="lax"
        )


async def create_session(
    db: AsyncSession, svc: Services, *, tenant_id: UUID, user_id: UUID
) -> tuple[str, UUID]:
    """Insert a new session in the caller's tenant transaction. Returns (token, session ID)."""
    token, session_id = new_token(), uuid4()
    await db.execute(
        insert(Session).values(
            id=session_id,
            tenant_id=tenant_id,
            user_id=user_id,
            token_hash=hash_token(token),
            # Database clock, so it lines up exactly with created_at (12 h CHECK).
            expires_at=func.now() + timedelta(hours=svc.settings.session_absolute_hours),
        )
    )
    return token, session_id


async def resolve(svc: Services, token: str | None) -> Any | None:
    """Look up a live session by its token (through the SECURITY DEFINER function)."""
    if not token or len(token) > _MAX_TOKEN_CHARS:
        return None
    async with system_scope(svc.session_factory) as db:
        return (
            await db.execute(
                text("SELECT * FROM skyline.resolve_session(:h, make_interval(mins => :idle))"),
                {"h": hash_token(token), "idle": svc.settings.session_idle_minutes},
            )
        ).first()


async def authenticate(request: Request, svc: ServicesDep) -> Principal:
    """Resolve the session cookie into a principal, or raise 401."""
    cached: Principal | None = getattr(request.state, "principal", None)
    if cached is not None:
        return cached
    token = request.cookies.get(SESSION_COOKIE)
    row = await resolve(svc, token)
    if row is None or token is None:
        raise ApiError(401, "unauthenticated", "Sign in to continue")
    if datetime.now(UTC) - row.last_seen_at > _TOUCH_AFTER:
        # The one write a GET may cause: the idle-timeout touch (rate-limited to once a
        # minute). Nothing else in a safe request changes state (ADR-0008).
        async with tenant_scope(svc.session_factory, row.tenant_id) as db:
            await db.execute(
                update(Session)
                .where(Session.tenant_id == row.tenant_id, Session.id == row.session_id)
                .values(last_seen_at=func.now())
            )
    principal = Principal(
        user_id=row.user_id,
        tenant_id=row.tenant_id,
        role=row.role,
        session_id=row.session_id,
        token_hash=hash_token(token),
        must_change_password=row.must_change_password,
        ip=client_ip(request, svc),
    )
    request.state.principal = principal
    return principal


async def _deny(svc: Services, principal: Principal, action: AuditAction, request: Request) -> None:
    async with tenant_scope(svc.session_factory, principal.tenant_id) as db:
        await record_audit(
            db,
            action=action,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            outcome=AuditOutcome.DENIED,
            target_type="route",
            target_id=f"{request.method} {request.url.path}"[:200],
            ip=principal.ip,
        )


def _csrf_ok(request: Request, svc: Services, principal: Principal) -> bool:
    header = request.headers.get(CSRF_HEADER, "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    expected = csrf_token(svc, principal.session_id)
    return (
        bool(header)  # nosemgrep: nan-injection - string truthiness, no float parsing
        and constant_time_equals(header, cookie)
        and constant_time_equals(header, expected)
    )


def require(permission: Permission) -> Callable[..., Coroutine[Any, Any, Principal]]:
    """Dependency factory: the route needs ``permission`` (and a CSRF token if unsafe)."""

    async def dependency(
        request: Request,
        svc: ServicesDep,
        principal: Annotated[Principal, Depends(authenticate)],
    ) -> Principal:
        if request.method not in SAFE_METHODS and not _csrf_ok(request, svc, principal):
            await _deny(svc, principal, AuditAction.CSRF_REJECTED, request)
            raise ApiError(
                403, "csrf_failed", "The request could not be verified. Reload the page."
            )
        if principal.must_change_password and permission is not Permission.SELF:
            raise ApiError(403, "password_change_required", "Change your password to continue")
        if permission not in principal.permissions:
            if request.method in SAFE_METHODS:
                # GET/HEAD never write, not even an audit row: under SameSite=Lax a
                # cross-site link could otherwise make a viewer's session fill the log.
                _log.warning("permission_denied", route=request.url.path[:200])
            else:
                await _deny(svc, principal, AuditAction.PERMISSION_DENIED, request)
            raise ApiError(403, "forbidden", "You don't have permission to do that")
        return principal

    setattr(dependency, PERMISSION_ATTR, permission)
    return dependency


class TenantDb:
    """Opens tenant-scoped transactions for the current principal. GET/HEAD requests get a
    READ ONLY transaction, so PostgreSQL itself guarantees they never change state."""

    def __init__(self, svc: Services, principal: Principal, *, read_only: bool) -> None:
        self._svc = svc
        self.principal = principal
        self._read_only = read_only

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncSession]:
        async with tenant_scope(
            self._svc.session_factory, self.principal.tenant_id, read_only=self._read_only
        ) as db:
            yield db


async def tenant_db(
    request: Request, svc: ServicesDep, principal: Annotated[Principal, Depends(authenticate)]
) -> TenantDb:
    return TenantDb(svc, principal, read_only=request.method in SAFE_METHODS)


TenantDbDep = Annotated[TenantDb, Depends(tenant_db)]
