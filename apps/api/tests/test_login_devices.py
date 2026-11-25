"""Known-device login budgets (THREAT_MODEL R9, ADR-0008): an attacker who keeps an account
locked can't keep the real user's own browsers out, and device cookies can't be forged,
replayed against another account or kept past their lifetime."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from api_helpers import ORIGIN, api_settings, login, make_services, make_user

from skyline_api.app import create_app
from skyline_api.routes.auth import DEVICE_COOKIE, _device_token, _known_device, _subject
from skyline_api.settings import ApiSettings
from testsupport import Database, rewind_login_attempts

LOGIN = "/api/v1/auth/login"
WRONG = "wrong-password!!"


@asynccontextmanager
async def _attacker(db: Database, settings: ApiSettings) -> AsyncIterator[httpx.AsyncClient]:
    """Another browser on another network, with no device cookie."""
    app = create_app(settings, make_services(db, settings))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("198.51.100.66", 40000)),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
    ) as http:
        yield http


async def _lock_account(db: Database, settings: ApiSettings, email: str) -> None:
    """Guess as fast as allowed until the account is in its 5-minute lock."""
    async with _attacker(db, settings) as attacker:
        for wait in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
            assert (
                await attacker.post(LOGIN, json={"email": email, "password": WRONG})
            ).status_code == 401
            await rewind_login_attempts(db, wait)
        assert (
            await attacker.post(LOGIN, json={"email": email, "password": WRONG})
        ).status_code == 401
        locked = await attacker.post(LOGIN, json={"email": email, "password": WRONG})
        assert locked.status_code == 429 and int(locked.headers["Retry-After"]) >= 299


async def test_a_known_device_is_not_held_by_an_attackers_lock(
    db: Database, settings: ApiSettings, client: httpx.AsyncClient
) -> None:
    user = await make_user(db)
    assert (
        await client.post(LOGIN, json={"email": user.email, "password": user.password})
    ).status_code == 200
    assert DEVICE_COOKIE in client.cookies
    await client.post(
        "/api/v1/auth/logout", headers={"X-CSRF-Token": client.cookies["__Host-skyline_csrf"]}
    )
    await _lock_account(db, settings, user.email)
    # The real user's browser still gets in: its attempts are on its own budget.
    assert (
        await client.post(LOGIN, json={"email": user.email, "password": user.password})
    ).status_code == 200
    # Its own mistakes are throttled on the device, starting again at 1 second.
    assert (
        await client.post(LOGIN, json={"email": user.email, "password": WRONG})
    ).status_code == 401
    refused = await client.post(LOGIN, json={"email": user.email, "password": user.password})
    assert refused.status_code == 429 and refused.headers["Retry-After"] == "1"
    # A browser without the cookie is still held by the account's lock.
    async with _attacker(db, settings) as other:
        fresh = await other.post(LOGIN, json={"email": user.email, "password": user.password})
        assert fresh.status_code == 429


async def test_a_signed_in_user_can_change_password_while_the_account_is_locked(
    db: Database, settings: ApiSettings, client: httpx.AsyncClient
) -> None:
    user = await make_user(db)
    await login(client, user)
    await _lock_account(db, settings, user.email)
    changed = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": user.password, "new_password": "river-lamp-orbit-72"},
    )
    assert changed.status_code == 200, changed.text


async def test_a_device_cookie_only_counts_for_its_own_account(
    db: Database, settings: ApiSettings, client: httpx.AsyncClient
) -> None:
    owner, victim = await make_user(db), await make_user(db)
    assert (
        await client.post(LOGIN, json={"email": owner.email, "password": owner.password})
    ).status_code == 200
    await _lock_account(db, settings, victim.email)
    # The owner's device cookie is no use against someone else's account.
    replayed = await client.post(LOGIN, json={"email": victim.email, "password": victim.password})
    assert replayed.status_code == 429


async def test_the_device_cookie_is_hardened(db: Database, client: httpx.AsyncClient) -> None:
    user = await make_user(db)
    response = await client.post(LOGIN, json={"email": user.email, "password": user.password})
    header = next(h for h in response.headers.get_list("set-cookie") if h.startswith(DEVICE_COOKIE))
    attributes = {part.strip().lower() for part in header.split(";")[1:]}
    assert {"httponly", "secure", "path=/", "samesite=strict", "max-age=7776000"} <= attributes
    assert "domain" not in header.lower()


async def test_failed_sign_ins_never_mark_a_device(client: httpx.AsyncClient) -> None:
    response = await client.post(LOGIN, json={"email": "ghost@example.com", "password": WRONG})
    assert response.status_code == 401
    assert DEVICE_COOKIE not in client.cookies


def test_device_cookies_are_checked_strictly(db: Database) -> None:
    svc = make_services(db, api_settings(db, login_device_days=30))
    account = _subject(svc, b"account", "user@example.com")
    other = _subject(svc, b"account", "other@example.com")
    stored = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"  # stands in for the stored hash
    now = time.time()
    valid = _device_token(svc, account, stored)
    assert _known_device(svc, valid, account, stored) is not None
    assert _known_device(svc, valid, account, stored) == _known_device(svc, valid, account, stored)
    _, issued, nonce, mac = valid.split(".")
    forged = [
        None,
        "",
        valid + "x",  # MAC changed
        f"v1.{issued}.{nonce}X.{mac}",  # nonce changed
        f"v1.{int(issued) + 1}.{nonce}.{mac}",  # issue time changed
        f"v1.0{issued}.{nonce}.{mac}",  # same time, another spelling
        f"v2.{issued}.{nonce}.{mac}",  # unknown version
        f"v1.{issued}.{nonce}",  # missing part
        f"v1.-{issued}.{nonce}.{mac}",
        f"v1.{issued}.{nonce}.{mac}.extra",
        "v1." + "9" * 300,  # oversized
        f"v1.{issued}.{nonce}é.{mac}",  # non-ASCII
        _device_token(svc, account, stored, issued=int(now - 31 * 86_400)),  # expired
        _device_token(svc, account, stored, issued=int(now + 3600)),  # from the future
        _device_token(make_services(db, api_settings(db)), account, stored),  # another key
    ]
    for cookie in forged:
        assert _known_device(svc, cookie, account, stored) is None, cookie
    assert _known_device(svc, valid, other, stored) is None  # bound to its account
    assert _known_device(svc, valid, account, stored + "x") is None  # and to its password
    assert _known_device(svc, valid, account, None) is None  # no account: never a device


async def test_a_password_change_retires_every_earlier_device_cookie(
    db: Database, settings: ApiSettings, client: httpx.AsyncClient
) -> None:
    user = await make_user(db)
    assert (
        await client.post(LOGIN, json={"email": user.email, "password": user.password})
    ).status_code == 200  # browser A is now a known device
    new_password = "river-lamp-orbit-73"
    async with _attacker(db, settings) as browser_b:  # the user changes it elsewhere
        response = await browser_b.post(
            LOGIN, json={"email": user.email, "password": user.password}
        )
        browser_b.headers["X-CSRF-Token"] = browser_b.cookies["__Host-skyline_csrf"]
        assert response.status_code == 200
        changed = await browser_b.post(
            "/api/v1/auth/change-password",
            json={"current_password": user.password, "new_password": new_password},
        )
        assert changed.status_code == 200, changed.text
        await _lock_account(db, settings, user.email)
        # B got a cookie for the new password, so B is still a known device...
        relogin = await browser_b.post(LOGIN, json={"email": user.email, "password": new_password})
        assert relogin.status_code == 200
    # ...but A's cookie was earned with the old password: A is held by the account's lock.
    held = await client.post(LOGIN, json={"email": user.email, "password": new_password})
    assert held.status_code == 429
