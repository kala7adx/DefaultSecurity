"""Login, logout, current user, password change (ADR-0008, ARCHITECTURE §9).

Throttling is check-and-reserve in one step: ``skyline.begin_login_attempt`` takes a lock per
subject (account, IP bucket), counts recent failures and, if under budget, records this
attempt as a failure *before* the password is checked. ``finish_login_attempt`` then marks it
succeeded (or drops it if the request never got to check a password). So parallel requests
can't all slip past the check while argon2 runs: the budget holds under concurrency.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Literal
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
                ":account, :account_limit, :ip, :ip_limit, make_interval(mins => :window))"
            ),
            {
                "account": account,
                "account_limit": cfg.login_account_failures,
                "ip": ip,
                "ip_limit": cfg.login_ip_failures,
                "window": cfg.login_window_minutes,
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


def _too_many(retry_after: int) -> ApiError:
    return ApiError(
        429,
        "too_many_attempts",
        "Too many sign-in attempts. Try again later.",
        headers={"Retry-After": str(max(1, retry_after))},
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
) -> None:
    """A tenant-scoped row, so the tenant's admins see attacks on their own accounts."""
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
            details={"subject": _subject_ref(subject)},
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
    svc: Services, action: AuditAction, ip: str | None, known: Any, subject: bytes
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
        attempt = await _begin_attempt(svc, db, account, _subject(svc, b"ip", bucket))
        # Looked up whatever the outcome, so every path does the same database work.
        rows = (
            await db.execute(text("SELECT * FROM skyline.auth_lookup_user(:e)"), {"e": email})
        ).all()
    known = rows[0] if rows else None
    if not attempt.allowed:
        return _deferred(
            _too_many(attempt.retry_after),
            BackgroundTask(_audit_failure, svc, AuditAction.LOGIN_THROTTLED, ip, known, account),
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
            BackgroundTask(_audit_failure, svc, AuditAction.LOGIN_FAILED, ip, known, account),
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
    svc: Services, principal: Principal, email: str, password: str
) -> None:
    """Throttled (same account budget as login) and audited in the user's tenant."""
    account = _subject(svc, b"account", email)
    async with system_scope(svc.session_factory) as db:
        attempt = await _begin_attempt(svc, db, account, None)
        rows = (
            await db.execute(text("SELECT * FROM skyline.auth_lookup_user(:e)"), {"e": email})
        ).all()
    if not attempt.allowed:
        await _audit_user(
            svc,
            action=AuditAction.PASSWORD_CHANGE_THROTTLED,
            tenant_id=principal.tenant_id,
            user_id=principal.user_id,
            outcome=AuditOutcome.DENIED,
            ip=principal.ip,
            subject=account,
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
        )
        raise ApiError(400, "invalid_credentials", "The current password is incorrect")


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    response: Response,
    svc: ServicesDep,
    principal: Annotated[Principal, Depends(require(Permission.SELF))],
) -> MeOut:
    async with tenant_scope(svc.session_factory, principal.tenant_id, read_only=True) as db:
        email = (
            await db.execute(select(User.email).where(User.id == principal.user_id))
        ).scalar_one()
    await _check_current_password(svc, principal, email, body.current_password)
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
    return await _me(
        svc,
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        role=principal.role,
        must_change=False,
    )
