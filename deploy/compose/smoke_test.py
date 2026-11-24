# ruff: noqa: S101, PLR2004 - a smoke test script: plain asserts and literal HTTP codes
"""Smoke test: the Phase 0 Definition of Done against a running Compose stack, through the web
proxy on localhost:3000 (`uv run python deploy/compose/smoke_test.py` after `compose up -d`).
It changes the bootstrap password to a random one it never prints: use a throwaway stack (CI)
or reset afterwards with `docker compose down -v`.
The bootstrap password is read from the secrets volume and never printed. Python's cookie
jar won't send Secure cookies over http://localhost (browsers do), so cookies are handled
by hand here.
"""

import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

BASE = "http://localhost:3000"
DOCKER = shutil.which("docker") or "docker"
COMPOSE = [DOCKER, "compose", "-f", str(Path(__file__).with_name("docker-compose.yml"))]
FIXES = ["remove_public_ip", "close_admin_ports", "encrypt_bucket", "enable_mfa", "upgrade_os"]


def bootstrap_password() -> str:
    out = subprocess.run(  # noqa: S603 - fixed argv
        [
            *COMPOSE,
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "--entrypoint",
            "cat",
            "secrets-init",
            "/secrets/admin/bootstrap_admin_password",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


class Browserish:
    def __init__(self) -> None:
        self.http = httpx.Client(base_url=BASE, timeout=30)
        self.cookies: dict[str, str] = {}

    def _remember(self, response: httpx.Response) -> None:
        for header in response.headers.get_list("set-cookie"):
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0]
            if "max-age=0" in header.lower() or not value:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = value

    def call(self, method: str, path: str, json: object | None = None) -> httpx.Response:
        headers = {"Origin": BASE, "Sec-Fetch-Site": "same-origin"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if method != "GET" and "__Host-skyline_csrf" in self.cookies:
            headers["X-CSRF-Token"] = self.cookies["__Host-skyline_csrf"]
        response = self.http.request(method, path, json=json, headers=headers)
        self._remember(response)
        return response


def wait(what: str, check, timeout: float = 90) -> object:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(1)
    sys.exit(f"timed out waiting for {what}")


def _page_with(page: dict[str, Any], total: int) -> dict[str, Any] | None:
    return page if page["total"] == total else None


def main() -> None:
    b = Browserish()
    login_page = b.call("GET", "/login")
    csp = login_page.headers.get("content-security-policy", "")
    assert login_page.status_code == 200 and "nonce-" in csp and "frame-ancestors 'none'" in csp
    print("login page: 200, nonce CSP present")

    password = bootstrap_password()
    r = b.call("POST", "/api/v1/auth/login", {"email": "admin@example.com", "password": password})
    assert r.status_code == 200, r.status_code
    assert r.json()["must_change_password"] is True
    cookie_flags = [
        h for h in r.headers.get_list("set-cookie") if h.startswith("__Host-skyline_session")
    ]
    assert all(f in cookie_flags[0] for f in ("HttpOnly", "Secure", "SameSite=lax", "Path=/")), (
        cookie_flags
    )
    print("login: 200, forced password change required, hardened session cookie")

    blocked = b.call("GET", "/api/v1/findings")
    assert (
        blocked.status_code == 403 and blocked.json()["error"]["code"] == "password_change_required"
    )
    new_password = "e2e-" + secrets.token_urlsafe(18)
    r = b.call(
        "POST",
        "/api/v1/auth/change-password",
        {"current_password": password, "new_password": new_password},
    )
    assert r.status_code == 200, r.text
    print("password changed; old session revoked, new one issued")

    r = b.call("POST", "/api/v1/integrations", {"provider": "fake", "name": "Demo company"})
    assert r.status_code == 201, r.text
    integration_id = r.json()["id"]
    wait(
        "connected",
        lambda: (
            b.call("GET", f"/api/v1/integrations/{integration_id}").json()["status"] == "connected"
        ),
    )
    findings = wait(
        "5 findings",
        lambda: _page_with(b.call("GET", "/api/v1/findings").json(), 5),
    )
    print(f"onboarding scan: {findings['total']} open findings")

    frameworks: set[str] = set()
    for item in findings["items"]:
        detail = b.call("GET", f"/api/v1/findings/{item['id']}").json()
        frameworks |= {c["framework_id"] for c in detail["controls"]}
        print(
            f"  {item['severity']:<8} {item['check_id']:<40} -> "
            + ", ".join(f"{c['framework_id']} {c['ref']}" for c in detail["controls"])
        )
    assert {"cyber-essentials-3.3", "iso27001-2022"} <= frameworks

    r = b.call(
        "PATCH", f"/api/v1/integrations/{integration_id}", {"config": {"simulate_fixes": FIXES}}
    )
    assert r.status_code == 200, r.text
    resolved = wait(
        "5 resolved",
        lambda: _page_with(b.call("GET", "/api/v1/findings?status=resolved").json(), 5),
        timeout=120,
    )
    still_open = b.call("GET", "/api/v1/findings").json()["total"]
    print(f"after simulated fixes: {resolved['total']} auto-resolved, {still_open} open")
    assert still_open == 0

    # Deep link while signed out: the page loads (the app then redirects to /login?next=...).
    anon = httpx.get(f"{BASE}/findings/{findings['items'][0]['id']}", timeout=30)
    assert anon.status_code == 200
    cross = httpx.post(
        f"{BASE}/api/v1/integrations",
        json={},
        headers={"Origin": "https://evil.example"},
        timeout=30,
    )
    assert cross.status_code == 403
    print("deep link page served signed-out; cross-origin POST refused (403)")
    print("E2E OK")


if __name__ == "__main__":
    main()
