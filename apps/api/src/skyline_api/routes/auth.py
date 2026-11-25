"""Login, logout, current user, password change (ADR-0008, ARCHITECTURE §9).

Throttling is check-and-reserve in one step: ``skyline.begin_login_attempt`` takes a lock per
subject (account, IP bucket), checks the account's progressive wait and the sliding-window
ceilings and, if allowed, records this attempt as a failure *before* the password is checked.
``finish_login_attempt`` then marks it succeeded (or drops it if the request never got to
check a password). So parallel requests can't all slip past the check while argon2 runs: a
reservation starts the next wait at once, so guesses are spaced by the wait however many
requests arrive together.

Known devices (OWASP's device-cookie defence): a successful sign-in sets a signed cookie bound
to that account and to its current password hash. A browser presenting a valid one is
throttled on its own subject instead of the account's, so an attacker who keeps the account
locked can't keep the real user's own devices out. Unknown, forged, expired or other-account
cookies, and every cookie issued before a password change, fall back to the account.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from skyline_api.auth import (
    SESSION_COOKIE,
    Principal,
    ServicesDep,
    clear_session_cookies,
    client_ip,
    create_session,
    ip_bucket,
    require,
    resolve,
    set_session_cookies,
)
from skyline_api.errors import ApiError, error_body
from skyline_api.rbac import Permission, permissions_for
from skyline_api.schemas import ChangePasswordRequest, LoginRequest, MeOut, TenantOut
from skyline_api.services import Services
from skyline_core.audit import AuditAction, record_audit
from skyline_core.db.models import ActorType, AuditOutcome, Session, Tenant, User
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.logging import get_logger
from skyline_core.security.passwords import (
    PasswordPolicyError,
    check_password_policy,
    hash_password,
    verify_password,
)
from skyline_core.security.tokens import hmac_sha256

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
_log = get_logger(__name__)


def _invalid_credentials() -> ApiError:
    # A fresh instance per raise: a shared one would chain tracebacks (and their frames,
    # passwords included) across requests.
    return ApiError(401, "invalid_credentials", "The email or password is incorrect")


def _busy() -> ApiError:
    return ApiError(
        503, "busy", "The service is busy. Try again shortly.", headers={"Retry-After": "1"}
    )


@asynccontextmanager
async def _hash_slot(svc: Services, ip_key: str) -> AsyncIterator[None]:
    """One of ``max_concurrent_hashes`` argon2 slots (CPU and 64 MiB each), and at most
    ``max_concurrent_hashes_per_ip`` per IP bucket, so one source can't take them all.
    Taken only after the attempt is reserved, and never waited for: full means 503."""
    per_ip = svc.hashing_by_ip.get(ip_key, 0)
    if svc.hash_slots.locked() or per_ip >= svc.settings.max_concurrent_hashes_per_ip:
        raise _busy()
    svc.hashing_by_ip[ip_key] = per_ip + 1
    try:
        async with svc.hash_slots:
            yield
    finally:
        remaining = svc.hashing_by_ip.get(ip_key, 1) - 1
        if remaining > 0:
            svc.hashing_by_ip[ip_key] = remaining
        else:
            svc.hashing_by_ip.pop(ip_key, None)


def _subject(svc: Services, kind: bytes, value: str) -> bytes:
    """Throttling key: an HMAC, so the table never holds emails or IPs."""
    return hmac_sha256(svc.session_key.reveal(), b"login", kind, value.encode())


DEVICE_COOKIE: Final = "__Host-skyline_device"
_DEVICE_VERSION: Final = "v1"
_DEVICE_PARTS: Final = 4
_DEVICE_COOKIE_MAX: Final = 200
_DAY: Final = 86_400
_CLOCK_SKEW: Final = 60


#: Stands in for the credential of an email with no account, so the check costs the same.
_NO_ACCOUNT: Final = "skyline:no-account"


def _credential(password_hash: str | None) -> bytes:
    """A fingerprint of the stored hash: a device cookie dies with the password it was earned
    with, so cookies collected by someone who once knew the password are worthless after the
    change. Unknown emails hash the stand-in, so both cases do the same work."""
    return hashlib.sha256((password_hash or _NO_ACCOUNT).encode()).digest()


def _device_mac(
    svc: Services, account: bytes, password_hash: str | None, issued: int, nonce: str
) -> str:
    mac = hmac_sha256(
        svc.session_key.reveal(),
        b"login-device",
        account,
        _credential(password_hash),
        str(issued).encode(),
        nonce.encode(),
    )
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def _device_token(
    svc: Services,
    account: bytes,
    password_hash: str,
    *,
    issued: int | None = None,
    nonce: str | None = None,
) -> str:
    """``v1.<issued>.<nonce>.<mac>``: the MAC binds the nonce to one account and password."""
    issued = int(time.time()) if issued is None else issued
    nonce = secrets.token_urlsafe(16) if nonce is None else nonce
    mac = _device_mac(svc, account, password_hash, issued, nonce)
    return ".".join((_DEVICE_VERSION, str(issued), nonce, mac))


def _parse_device(cookie: str | None) -> tuple[int, str, str] | None:
    """``(issued, nonce, mac)`` of a well-formed cookie, or None."""
    if not cookie or len(cookie) > _DEVICE_COOKIE_MAX or not cookie.isascii():
        return None
    parts = cookie.split(".")
    if len(parts) != _DEVICE_PARTS or parts[0] != _DEVICE_VERSION or not parts[1].isdigit():
        return None
    issued = int(parts[1])
    if parts[1] != str(issued):  # one spelling per time (no leading zeros)
        return None
    return issued, parts[2], parts[3]


def _known_device(
    svc: Services,
    cookie: str | None,
    account: bytes,
    password_hash: str | None,
    *,
    now: float | None = None,
) -> bytes | None:
    """The throttling subject of a valid device cookie for this account and its current
    password, or None. Emails without an account do the same work and always get None."""
    parsed = _parse_device(cookie)
    if parsed is None:
        return None
    issued, nonce, mac = parsed
    now = time.time() if now is None else now
    if not now - svc.settings.login_device_days * _DAY <= issued <= now + _CLOCK_SKEW:
        return None
    valid = hmac.compare_digest(mac, _device_mac(svc, account, password_hash, issued, nonce))
    if not valid or password_hash is None:
        return None
    return _subject(svc, b"device", f"{account.hex()}.{nonce}")


def _remember_device(response: Response, svc: Services, account: bytes, password_hash: str) -> None:
    """A fresh device cookie after every successful password check (new nonce, new budget)."""
    response.set_cookie(
        DEVICE_COOKIE,
        _device_token(svc, account, password_hash),
        max_age=svc.settings.login_device_days * _DAY,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _subject_ref(subject: bytes) -> str:
    """A short, non-reversible reference for audit rows (correlates attempts on one account)."""
    return subject.hex()[:16]


@dataclass(frozen=True, slots=True)
class _Attempt:
    allowed: bool
    retry_after: int
    ids: Sequence[int]


async def _begin_attempt(
    svc: Services, db: AsyncSession, account: bytes, ip: bytes | None
) -> _Attempt:
    cfg = svc.settings
    row = (
        await db.execute(
            text(
                "SELECT * FROM skyline.begin_login_attempt("
                ":account, :account_limit, :ip, :ip_limit, make_interval(mins => :window),"
                " make_interval(secs => :first_wait), make_interval(secs => :lock),"
                " make_interval(mins => :streak_reset))"
            ),
            {
                "account": account,
                "account_limit": cfg.login_account_failures,
                "ip": ip,
                "ip_limit": cfg.login_ip_failures,
                "window": cfg.login_window_minutes,
                "first_wait": cfg.login_first_wait_ms / 1000,
                "lock": cfg.login_lock_seconds,
                "streak_reset": cfg.login_streak_reset_minutes,
            },
        )
    ).one()
    return _Attempt(row.allowed, row.retry_after, list(row.attempt_ids or []))


async def _finish_attempt(
    svc: Services, attempt: _Attempt, outcome: Literal["succeeded", "failed", "cancelled"]
) -> None:
    if not attempt.ids or outcome == "failed":
        return  # reserved attempts already count as failures
    async with system_scope(svc.session_factory) as db:
        await db.execute(
            text("SELECT skyline.finish_login_attempt(:ids, :outcome)"),
            {"ids": list(attempt.ids), "outcome": outcome},
        )


async def _me(
    svc: Services, *, tenant_id: UUID, user_id: UUID, role: str, must_change: bool
) -> MeOut:
    async with tenant_scope(svc.session_factory, tenant_id, read_only=True) as db:
        email = (await db.execute(select(User.email).where(User.id == user_id))).scalar_one()
        tenant = (
            await db.execute(
                select(Tenant.id, Tenant.slug, Tenant.name).where(Tenant.id == tenant_id)
            )
        ).one()
    return MeOut(
        user_id=user_id,
        email=email,
        role=role,
        permissions=sorted(p.value for p in permissions_for(role)),
        must_change_password=must_change,
        tenant=TenantOut(id=tenant.id, slug=tenant.slug, name=tenant.name),
    )


_MINUTE = 60


def _wait_text(seconds: int) -> str:
    if seconds < _MINUTE:
        return "1 second" if seconds == 1 else f"{seconds} seconds"
    minutes = -(-seconds // _MINUTE)  # rounded up: never promise less than the real wait
    return "1 minute" if minutes == 1 else f"{minutes} minutes"


def _too_many(retry_after: int) -> ApiError:
    """The wait is the same for known and unknown emails (both are throttled by subject)."""
    seconds = max(1, retry_after)
    return ApiError(
        429,
        "too_many_attempts",
        f"Too many sign-in attempts. Try again in {_wait_text(seconds)}.",
        headers={"Retry-After": str(seconds)},
    )


async def _audit_anonymous(svc: Services, action: AuditAction, ip: str | None) -> None:
    async with system_scope(svc.session_factory) as db:
        await record_audit(
            db,
            action=action,
            tenant_id=None,
            actor_type=ActorType.ANONYMOUS,
            outcome=AuditOutcome.DENIED
            if action is AuditAction.LOGIN_THROTTLED
            else AuditOutcome.FAILURE,
            ip=ip,
        )


async def _audit_user(
    svc: Services,
    *,
    action: AuditAction,
    tenant_id: UUID,
    user_id: UUID,
    outcome: AuditOutcome,
    ip: str | None,
    subject: bytes,
    via: Literal["account", "device"],
) -> None:
    """A tenant-scoped row, so the tenant's admins see attacks on their own accounts.
    ``via`` says whose budget the attempt used: the account's or a known device's."""
    async with tenant_scope(svc.session_factory, tenant_id) as db:
        await record_audit(
            db,
            action=action,
            tenant_id=tenant_id,
            actor_type=ActorType.USER,
            actor_id=user_id,
            outcome=outcome,
            target_type="user",
            target_id=user_id,
            details={"subject": _subject_ref(subject), "via": via},
            ip=ip,
        )


async def _revoke_existing(svc: Services, request: Request) -> None:
    """Session fixation defence: a login always ends any session the browser already had."""
    row = await resolve(svc, request.cookies.get(SESSION_COOKIE))
    if row is not None:
        async with tenant_scope(svc.session_factory, row.tenant_id) as db:
            await db.execute(
                update(Session)
                .where(Session.tenant_id == row.tenant_id, Session.id == row.session_id)
                .values(revoked_at=func.now())
            )


async def _audit_failure(
    svc: Services,
    action: AuditAction,
    ip: str | None,
    known: Any,
    subject: bytes,
    via: Literal["account", "device"],
) -> None:
    """Anonymous row always; a tenant row too when the email belongs to an account."""
    try:
        await _audit_anonymous(svc, action, ip)
        if known is not None:
            await _audit_user(
                svc,
                action=action,
                tenant_id=known.tenant_id,
                user_id=known.user_id,
                outcome=AuditOutcome.DENIED
                if action is AuditAction.LOGIN_THROTTLED
                else AuditOutcome.FAILURE,
                ip=ip,
                subject=subject,
                via=via,
            )
    except Exception:  # the response is already sent; never lose the error silently
        _log.exception("login_audit_failed")


def _deferred(error: ApiError, audit: BackgroundTask) -> JSONResponse:
    """The error response now, its audit rows afterwards: response timing must not depend
    on whether the email belongs to an account (no enumeration by timing)."""
    return JSONResponse(
        error_body(error.code, error.message),
        status_code=error.status,
        headers=error.headers,
        background=audit,
    )


@router.post("/login", response_model=MeOut)
async def login(
    body: LoginRequest, request: Request, response: Response, svc: ServicesDep
) -> MeOut | JSONResponse:
    email = body.email.strip().lower()
    ip = client_ip(request, svc)
    bucket = ip_bucket(ip)
    account = _subject(svc, b"account", email)
    async with system_scope(svc.session_factory) as db:
        # Looked up whatever the outcome, so every path does the same database work.
        rows = (
            await db.execute(text("SELECT * FROM skyline.auth_lookup_user(:e)"), {"e": email})
        ).all()
        known = rows[0] if rows else None
        device = _known_device(
            svc,
            request.cookies.get(DEVICE_COOKIE),
            account,
            known.password_hash if known else None,
        )
        attempt = await _begin_attempt(svc, db, device or account, _subject(svc, b"ip", bucket))
    via: Literal["account", "device"] = "device" if device else "account"
    if not attempt.allowed:
        return _deferred(
            _too_many(attempt.retry_after),
            BackgroundTask(
                _audit_failure, svc, AuditAction.LOGIN_THROTTLED, ip, known, account, via
            ),
        )
    try:
        async with _hash_slot(svc, bucket):
            # argon2 is CPU-bound: keep the event loop free. Unknown users verify a dummy hash.
            ok = await asyncio.to_thread(
                verify_password, known.password_hash if known else None, body.password
            )
    except BaseException:
        # Never got to check (busy, or cancelled): the reservation doesn't count.
        await _finish_attempt(svc, attempt, "cancelled")
        raise
    await _finish_attempt(svc, attempt, "succeeded" if ok else "failed")
    if not ok:
        return _deferred(
            _invalid_credentials(),
            BackgroundTask(_audit_failure, svc, AuditAction.LOGIN_FAILED, ip, known, account, via),
        )
    await _revoke_existing(svc, request)
    user = rows[0]
    async with tenant_scope(svc.session_factory, user.tenant_id) as db:
        token, session_id = await create_session(
            db, svc, tenant_id=user.tenant_id, user_id=user.user_id
        )
        await db.execute(
            update(User).where(User.id == user.user_id).values(last_login_at=func.now())
        )
        await record_audit(
            db,
            action=AuditAction.LOGIN_SUCCEEDED,
            tenant_id=user.tenant_id,
            actor_type=ActorType.USER,
            actor_id=user.user_id,
            ip=ip,
        )
    set_session_cookies(response, svc, token, session_id)
    _remember_device(response, svc, account, user.password_hash)
    return await _me(
        svc,
        tenant_id=user.tenant_id,
        user_id=user.user_id,
        role=user.role,
        must_change=user.must_change_password,
    )


@router.post("/logout", status_code=204)
async def logout(
    svc: ServicesDep, principal: Annotated[Principal, Depends(require(Permission.SELF))]
) -> Response:
    async with tenant_scope(svc.session_factory, principal.tenant_id) as db:
        await db.execute(
            update(Session)
            .where(Session.tenant_id == principal.tenant_id, Session.id == principal.session_id)
            .values(revoked_at=func.now())
        )
        await record_audit(
            db,
            action=AuditAction.LOGOUT,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            ip=principal.ip,
        )
    response = Response(status_code=204)
    clear_session_cookies(response)
    return response


@router.get("/me")
async def me(
    svc: ServicesDep, principal: Annotated[Principal, Depends(require(Permission.SELF))]
) -> MeOut:
    return await _me(
        svc,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        role=principal.role,
        must_change=principal.must_change_password,
    )


async def _check_current_password(
    svc: Services, principal: Principal, email: str, password: str, device_cookie: str | None
) -> None:
    """Throttled like login (the device's budget, else the account's) and audited in the
    user's tenant."""
    account = _subject(svc, b"account", email)
    async with system_scope(svc.session_factory) as db:
        rows = (
            await db.execute(text("SELECT * FROM skyline.auth_lookup_user(:e)"), {"e": email})
        ).all()
        stored = rows[0].password_hash if rows else None
        device = _known_device(svc, device_cookie, account, stored)
        attempt = await _begin_attempt(svc, db, device or account, None)
    via: Literal["account", "device"] = "device" if device else "account"
    if not attempt.allowed:
        await _audit_user(
            svc,
            action=AuditAction.PASSWORD_CHANGE_THROTTLED,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            outcome=AuditOutcome.DENIED,
            ip=principal.ip,
            subject=account,
            via=via,
        )
        raise _too_many(attempt.retry_after)
    try:
        async with _hash_slot(svc, ip_bucket(principal.ip)):
            ok = await asyncio.to_thread(
                verify_password, rows[0].password_hash if rows else None, password
            )
    except BaseException:
        await _finish_attempt(svc, attempt, "cancelled")
        raise
    await _finish_attempt(svc, attempt, "succeeded" if ok else "failed")
    if not ok:
        await _audit_user(
            svc,
            action=AuditAction.PASSWORD_CHANGE_FAILED,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            outcome=AuditOutcome.FAILURE,
            ip=principal.ip,
            subject=account,
            via=via,
        )
        raise ApiError(400, "invalid_credentials", "The current password is incorrect")


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    svc: ServicesDep,
    principal: Annotated[Principal, Depends(require(Permission.SELF))],
) -> MeOut:
    async with tenant_scope(svc.session_factory, principal.tenant_id, read_only=True) as db:
        email = (
            await db.execute(select(User.email).where(User.id == principal.user_id))
        ).scalar_one()
    await _check_current_password(
        svc, principal, email, body.current_password, request.cookies.get(DEVICE_COOKIE)
    )
    if body.new_password == body.current_password:
        raise ApiError(422, "password_policy", "Choose a password you haven't used here before")
    try:
        check_password_policy(body.new_password, email=email)
    except PasswordPolicyError as exc:
        raise ApiError(
            422, "password_policy", f"The new password is not allowed ({exc.violation.value})"
        ) from None
    async with _hash_slot(svc, ip_bucket(principal.ip)):
        new_hash = await asyncio.to_thread(hash_password, body.new_password)
    async with system_scope(svc.session_factory) as db:
        changed = (
            await db.execute(
                text("SELECT skyline.change_password(:h, :p, make_interval(mins => :idle))"),
                {
                    "h": principal.token_hash,
                    "p": new_hash,
                    "idle": svc.settings.session_idle_minutes,
                },
            )
        ).scalar()
    if changed is None:
        raise ApiError(401, "unauthenticated", "Sign in to continue")
    # Every session of this user was revoked; issue a fresh one for this browser.
    async with tenant_scope(svc.session_factory, principal.tenant_id) as db:
        token, session_id = await create_session(
            db, svc, tenant_id=principal.tenant_id, user_id=principal.user_id
        )
        await record_audit(
            db,
            action=AuditAction.PASSWORD_CHANGED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            ip=principal.ip,
        )
    set_session_cookies(response, svc, token, session_id)
    # Every earlier device cookie of this account died with the old hash; this browser
    # gets one for the new password.
    _remember_device(response, svc, _subject(svc, b"account", email), new_hash)
    return await _me(
        svc,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        role=principal.role,
        must_change=False,
    )
