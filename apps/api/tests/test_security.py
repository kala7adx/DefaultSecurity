"""Route-level security: deny by default, CSRF, Origin, headers, errors, sessions (ADR-0008)."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
from api_helpers import ORIGIN, User, api_settings, login, make_services, make_user
from fastapi.routing import APIRoute
from sqlalchemy import select

from skyline_api.app import PUBLIC_ROUTES, create_app
from skyline_api.auth import CSRF_COOKIE, PERMISSION_ATTR, SESSION_COOKIE, ip_bucket
from skyline_api.middleware import SAFE_METHODS
from skyline_core.db.models import AuditLog
from skyline_core.db.tenancy import tenant_scope
from skyline_core.settings import Environment
from testsupport import Database

pytestmark = pytest.mark.db


def _permissions(dependant: Any) -> set[object]:
    found: set[object] = set()
    for dep in dependant.dependencies:
        marker = getattr(dep.call, PERMISSION_ATTR, None)
        if marker is not None:
            found.add(marker)
        found |= _permissions(dep)
    return found


def _routes(db: Database) -> list[APIRoute]:
    settings = api_settings(db)
    app = create_app(settings, make_services(db, settings))
    return [r for r in app.routes if isinstance(r, APIRoute)]


def test_every_route_declares_a_permission_except_the_public_set(db: Database) -> None:
    missing, public_with_permission = [], []
    for route in _routes(db):
        for method in route.methods:
            key = (method, route.path)
            perms = _permissions(route.dependant)
            if key in PUBLIC_ROUTES:
                if perms:
                    public_with_permission.append(key)
            elif len(perms) != 1:
                missing.append(key)
    assert missing == []
    assert public_with_permission == []


def test_state_changing_routes_never_use_safe_methods(db: Database) -> None:
    # Safe methods run in READ ONLY transactions; anything that writes must be POST/PATCH/DELETE.
    writers = {"create", "update", "delete", "start", "revoke", "test", "login", "logout", "change"}
    for route in _routes(db):
        if route.methods & SAFE_METHODS:
            assert not any(word in route.name for word in writers), route.name


def test_the_api_does_not_load_collection_code() -> None:
    code = (
        "import sys, skyline_api.app;"
        "bad = [m for m in sys.modules if m.endswith('.transport') or m.split('.')[0] in "
        "('boto3','botocore','httpx','skyline_worker')];"
        "print(','.join(bad))"
    )
    result = subprocess.run(  # noqa: S603 - fixed argument list, no shell
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, timeout=60
    )
    assert result.stdout.strip() == ""


async def test_unauthenticated_requests_are_refused(client: httpx.AsyncClient) -> None:
    for path in ("/api/v1/findings", "/api/v1/auth/me", "/api/v1/integrations"):
        response = await client.get(path)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unauthenticated"


async def test_login_sets_hardened_cookies(client: httpx.AsyncClient, admin: User) -> None:
    response = await login(client, admin)
    cookies = {c.split("=", 1)[0]: c.lower() for c in response.headers.get_list("set-cookie")}
    session, csrf = cookies[SESSION_COOKIE], cookies[CSRF_COOKIE]
    for cookie in (session, csrf):
        assert "secure" in cookie and "path=/" in cookie and "samesite=lax" in cookie
        assert "domain=" not in cookie
    assert "httponly" in session
    assert "httponly" not in csrf
    body = response.json()
    assert body["role"] == "admin" and "integrations:write" in body["permissions"]


async def test_wrong_and_unknown_credentials_look_the_same(
    client: httpx.AsyncClient, admin: User
) -> None:
    wrong = await client.post(
        "/api/v1/auth/login", json={"email": admin.email, "password": "nope-nope-nope"}
    )
    unknown = await client.post(
        "/api/v1/auth/login", json={"email": "ghost@example.com", "password": "nope-nope-nope"}
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]
    assert SESSION_COOKIE not in wrong.cookies


async def test_login_is_throttled(db: Database, client: httpx.AsyncClient) -> None:
    user = await make_user(db)
    for _ in range(10):
        response = await client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": "wrong-password!!"}
        )
        assert response.status_code == 401
    throttled = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": user.password}
    )
    assert throttled.status_code == 429
    assert 1 <= int(throttled.headers["Retry-After"]) <= 300


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.example"},
        {"Origin": ""},
        {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"},
        {"Origin": ORIGIN, "Sec-Fetch-Site": "same-site"},
    ],
)
async def test_cross_origin_unsafe_requests_are_refused(
    signed_in: httpx.AsyncClient, headers: dict[str, str]
) -> None:
    for name, value in headers.items():
        signed_in.headers[name] = value
    if headers.get("Origin") == "":
        del signed_in.headers["Origin"]
    response = await signed_in.post("/api/v1/auth/logout")
    assert response.status_code == 403
    login_attempt = await signed_in.post(
        "/api/v1/auth/login", json={"email": "a@b.co", "password": "x"}
    )
    assert login_attempt.status_code == 403  # login CSRF is blocked too


@pytest.mark.parametrize("token", [None, "", "forged-token"])
async def test_csrf_token_is_required_and_audited(
    db: Database, signed_in: httpx.AsyncClient, admin: User, token: str | None
) -> None:
    if token is None:
        del signed_in.headers["X-CSRF-Token"]
    else:
        signed_in.headers["X-CSRF-Token"] = token
    response = await signed_in.post("/api/v1/integrations", json={"provider": "fake", "name": "x"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"
    async with tenant_scope(db.factory("skyline_api"), admin.tenant.id) as session:
        actions = set((await session.execute(select(AuditLog.action))).scalars())
    assert "authz.csrf_rejected" in actions


async def test_csrf_token_from_another_session_is_rejected(
    db: Database, client: httpx.AsyncClient, admin: User
) -> None:
    other = await make_user(db)
    await login(client, other)
    stolen = client.cookies[CSRF_COOKIE]
    client.cookies.clear()
    await login(client, admin)
    client.headers["X-CSRF-Token"] = stolen
    client.cookies.set(CSRF_COOKIE, stolen, domain="skyline.test")
    response = await client.post("/api/v1/integrations", json={"provider": "fake", "name": "x"})
    assert response.status_code == 403


async def test_logout_revokes_the_session(signed_in: httpx.AsyncClient) -> None:
    token = signed_in.cookies[SESSION_COOKIE]
    assert (await signed_in.post("/api/v1/auth/logout")).status_code == 204
    signed_in.cookies.set(SESSION_COOKIE, token, domain="skyline.test")
    assert (await signed_in.get("/api/v1/auth/me")).status_code == 401


async def test_login_rotates_any_existing_session(client: httpx.AsyncClient, admin: User) -> None:
    await login(client, admin)
    first = client.cookies[SESSION_COOKIE]
    await login(client, admin)
    assert client.cookies[SESSION_COOKIE] != first
    client.cookies.set(SESSION_COOKIE, first, domain="skyline.test")
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_forced_password_change(db: Database, client: httpx.AsyncClient) -> None:
    user = await make_user(db, must_change=True)
    me = (await login(client, user)).json()
    assert me["must_change_password"] is True
    blocked = await client.get("/api/v1/findings")
    assert blocked.status_code == 403
    assert blocked.json()["error"]["code"] == "password_change_required"
    old_session = client.cookies[SESSION_COOKIE]
    weak = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": user.password, "new_password": "Password1234"},
    )
    assert (weak.status_code, weak.json()["error"]["code"]) == (422, "password_policy")
    wrong = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "not-my-password", "new_password": "river-lamp-orbit-71"},
    )
    assert wrong.status_code == 400
    changed = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": user.password, "new_password": "river-lamp-orbit-71"},
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["must_change_password"] is False
    assert client.cookies[SESSION_COOKIE] != old_session
    client.headers["X-CSRF-Token"] = client.cookies[CSRF_COOKIE]
    assert (await client.get("/api/v1/findings")).status_code == 200
    # The old session died with the password change.
    client.cookies.set(SESSION_COOKIE, old_session, domain="skyline.test")
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_security_headers_and_correlation_ids(client: httpx.AsyncClient) -> None:
    request_id = str(uuid.uuid4())
    response = await client.get("/healthz", headers={"X-Request-ID": request_id})
    assert response.json() == {"status": "ok"}
    headers = response.headers
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in headers["content-security-policy"]
    assert "server" not in headers
    # The correlation ID (which lands in the audit log) is always the server's own.
    assert headers["x-request-id"] != request_id
    assert uuid.UUID(headers["x-request-id"])
    forged = await client.get("/healthz", headers={"X-Request-ID": "x\nlog-injection"})
    assert forged.headers["x-request-id"] != "x\nlog-injection"


async def test_readyz(client: httpx.AsyncClient) -> None:
    response = await client.get("/readyz")
    assert (response.status_code, response.json()) == (200, {"status": "ready"})


async def test_errors_are_generic_and_never_echo_input(signed_in: httpx.AsyncClient) -> None:
    secret = "do-not-echo-" + uuid.uuid4().hex
    response = await signed_in.post(
        "/api/v1/integrations", json={"provider": "fake", "name": "x", "unexpected": secret}
    )
    assert response.status_code == 422
    body = response.json()
    assert secret not in json.dumps(body)
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["correlation_id"]
    missing = await signed_in.get(f"/api/v1/integrations/{uuid.uuid4()}")
    assert missing.status_code == 404
    assert "Traceback" not in missing.text


async def test_oversized_bodies_are_rejected(signed_in: httpx.AsyncClient) -> None:
    body = b'{"name": "' + b"x" * (70 * 1024) + b'"}'
    response = await signed_in.post(
        "/api/v1/integrations", content=body, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413

    async def chunks() -> AsyncIterator[bytes]:  # no Content-Length: caught while streaming
        for start in range(0, len(body), 8192):
            yield body[start : start + 8192]

    streamed = await signed_in.post(
        "/api/v1/integrations", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert (streamed.status_code, streamed.json()["error"]["code"]) == (413, "payload_too_large")


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("POST", "/api/v1/auth/login", {"json": {"email": "a\x00@x.io", "password": "p"}}),
        ("POST", "/api/v1/auth/login", {"json": {"email": "a@x.io", "password": "p\x00"}}),
        ("GET", "/api/v1/assets", {"params": {"q": "web\x00"}}),
        ("GET", "/api/v1/findings", {"params": {"check_id": "x\x1b[31m"}}),
        ("GET", "/api/v1/audit-log", {"params": {"action": "\x00"}}),
    ],
)
async def test_control_characters_are_rejected_not_500(
    signed_in: httpx.AsyncClient, method: str, path: str, kwargs: dict[str, Any]
) -> None:
    response = await signed_in.request(method, path, **kwargs)
    assert response.status_code == 422, response.text


async def test_unhandled_errors_keep_headers_and_correlation_id(db: Database) -> None:
    settings = api_settings(db)
    app = create_app(settings, make_services(db, settings))

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("password=" + "z" * 12)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url=ORIGIN
    ) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    body = response.json()["error"]
    assert body["code"] == "internal_error"
    assert body["correlation_id"] == response.headers["x-request-id"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert "zzzz" not in response.text


async def test_denied_reads_are_not_written_to_the_audit_log(
    db: Database, client: httpx.AsyncClient
) -> None:
    from skyline_core.db.models import Role

    viewer = await make_user(db, Role.VIEWER)
    await login(client, viewer)
    assert (await client.get("/api/v1/audit-log")).status_code == 403
    async with tenant_scope(db.factory("skyline_api"), viewer.tenant.id) as session:
        denied = (
            await session.execute(select(AuditLog.id).where(AuditLog.action == "authz.denied"))
        ).all()
    assert denied == []


@pytest.mark.parametrize(
    ("ip", "bucket"),
    [
        (None, "unknown"),
        ("203.0.113.9", "203.0.113.9"),
        ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:ffff::9", "2001:db8:1:2::/64"),
        ("::ffff:198.51.100.7", "198.51.100.7"),
    ],
)
def test_ip_buckets(ip: str | None, bucket: str) -> None:
    assert ip_bucket(ip) == bucket


def test_production_needs_explicit_proxy_hops_and_defaults_hsts_on(db: Database) -> None:
    with pytest.raises(ValueError, match="TRUSTED_PROXY_HOPS"):
        api_settings(db, env=Environment.PRODUCTION)
    production = api_settings(db, env=Environment.PRODUCTION, trusted_proxy_hops=1)
    assert production.hsts_enabled and production.proxy_hops == 1
    assert not api_settings(db).hsts_enabled
    assert not api_settings(
        db, env=Environment.PRODUCTION, trusted_proxy_hops=1, hsts=False
    ).hsts_enabled


async def test_login_sheds_load_when_hashing_is_saturated(db: Database, admin: User) -> None:
    settings = api_settings(db)
    services = make_services(db, settings)
    app = create_app(settings, services)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
    ) as client:
        for _ in range(8):
            await services.hash_slots.acquire()
        try:
            response = await client.post(
                "/api/v1/auth/login", json={"email": admin.email, "password": admin.password}
            )
        finally:
            for _ in range(8):
                services.hash_slots.release()
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"


async def test_openapi_docs_are_off_outside_development(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/openapi.json")).status_code == 404
    assert (await client.get("/api/docs")).status_code == 404


async def _parallel_logins(
    db: Database, emails: list[str], password: str, ip: str, **settings_overrides: object
) -> list[int]:
    import asyncio
    import dataclasses

    settings_overrides.setdefault("max_concurrent_hashes_per_ip", 64)
    settings = api_settings(db, **settings_overrides)
    services = dataclasses.replace(
        make_services(db, settings), hash_slots=asyncio.Semaphore(len(emails))
    )
    app = create_app(settings, services)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, 1)),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
    ) as client:
        responses = await asyncio.gather(
            *(
                client.post("/api/v1/auth/login", json={"email": e, "password": password})
                for e in emails
            )
        )
    return [r.status_code for r in responses]


async def test_account_throttle_holds_under_parallel_requests(db: Database) -> None:
    user = await make_user(db)
    from pydantic import SecretStr

    password = "wrong-" + uuid.uuid4().hex
    key = SecretStr(uuid.uuid4().hex * 2)  # one throttling key across the calls below
    burst = await _parallel_logins(
        db, [user.email] * 30, password, "198.51.100.21", session_key=key
    )
    assert set(burst) <= {401, 429} and 1 <= burst.count(401) <= 10
    # Topping up one by one reaches the budget exactly, never more.
    rest: list[int] = []
    for _ in range(16):
        rest += await _parallel_logins(db, [user.email], password, "198.51.100.21", session_key=key)
    assert burst.count(401) + rest.count(401) == 10


async def test_ip_throttle_holds_under_parallel_requests(db: Database) -> None:
    emails = [f"nobody-{uuid.uuid4().hex[:8]}@example.com" for _ in range(25)]
    statuses = await _parallel_logins(db, emails, "wrong", "198.51.100.22", login_ip_failures=10)
    assert set(statuses) <= {401, 429} and 1 <= statuses.count(401) <= 10


async def test_failed_logins_on_known_accounts_reach_the_tenant_audit_log(
    db: Database, client: httpx.AsyncClient
) -> None:
    user = await make_user(db)
    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "wrong-" + uuid.uuid4().hex}
    )
    assert response.status_code == 401
    async with tenant_scope(db.factory("skyline_api"), user.tenant.id) as session:
        rows = (
            await session.execute(
                select(AuditLog.actor_id, AuditLog.details).where(
                    AuditLog.action == "auth.login.failed"
                )
            )
        ).all()
    assert [r.actor_id for r in rows] == [user.tenant.admin_id]
    assert len(rows[0].details["subject"]) == 16  # an HMAC reference, never the email


async def test_wrong_current_password_is_audited_in_the_tenant(
    db: Database, client: httpx.AsyncClient
) -> None:
    user = await make_user(db)
    await login(client, user)
    response = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "not-it-" + uuid.uuid4().hex, "new_password": "x" * 20},
    )
    assert response.status_code == 400
    async with tenant_scope(db.factory("skyline_api"), user.tenant.id) as session:
        actions = set(
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.actor_id == user.tenant.admin_id)
                )
            ).scalars()
        )
    assert "auth.password.change_failed" in actions


def test_default_ports_are_the_same_origin() -> None:
    from skyline_core.settings import validate_origin

    assert validate_origin("https://skyline.example:443") == "https://skyline.example"
    assert validate_origin("http://localhost:80") == "http://localhost"
    assert validate_origin("http://localhost:3000") == "http://localhost:3000"


async def test_one_ip_cannot_take_every_hashing_slot(db: Database) -> None:
    statuses = await _parallel_logins(
        db,
        [f"x-{uuid.uuid4().hex[:6]}@example.com" for _ in range(12)],
        "wrong",
        "198.51.100.23",
        max_concurrent_hashes_per_ip=2,
    )
    assert 503 in statuses and statuses.count(401) <= 12


def test_short_x_forwarded_for_falls_back_to_the_unknown_bucket(db: Database) -> None:
    from starlette.requests import Request

    from skyline_api.auth import client_ip

    settings = api_settings(db, trusted_proxy_hops=1)
    svc = make_services(db, settings)

    def request(xff: str | None) -> Request:
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return Request({"type": "http", "headers": headers, "client": ("10.0.0.5", 1)})

    assert client_ip(request("203.0.113.7"), svc) == "203.0.113.7"
    assert client_ip(request(None), svc) is None  # not the proxy's own address
    assert ip_bucket(client_ip(request(None), svc)) == "unknown"
