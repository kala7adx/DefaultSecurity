"""The Phase 0 Definition of Done through the API, plus RBAC and cross-tenant (IDOR) tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from api_helpers import ORIGIN, User, drain, login, make_services, make_user
from sqlalchemy import insert, select
from sqlalchemy.exc import DBAPIError

from skyline_api.auth import Principal, TenantDb
from skyline_core.db.models import AuditLog, Integration, Role
from skyline_core.db.tenancy import tenant_scope
from skyline_worker.runner import Worker
from testsupport import Database

pytestmark = pytest.mark.db

ALL_FIXES = ["remove_public_ip", "close_admin_ports", "encrypt_bucket", "enable_mfa", "upgrade_os"]


async def _connected_integration(client: httpx.AsyncClient, worker: Worker) -> dict[str, Any]:
    created = await client.post("/api/v1/integrations", json={"provider": "fake", "name": "Demo"})
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "verifying"
    assert await drain(worker) == 2  # verify, then the onboarding scan
    integration = (await client.get(f"/api/v1/integrations/{created.json()['id']}")).json()
    assert integration["status"] == "connected"
    return integration


async def test_end_to_end_findings_mute_and_auto_resolve(
    signed_in: httpx.AsyncClient, worker: Worker
) -> None:
    client = signed_in
    integration = await _connected_integration(client, worker)

    findings = (await client.get("/api/v1/findings")).json()
    assert findings["total"] == 5
    assert {f["check_id"] for f in findings["items"]} == {
        "fake.compute.vm_public_exposure",
        "fake.network.sg_admin_ports_open",
        "fake.storage.bucket_encryption",
        "fake.identity.admin_without_mfa",
        "fake.compute.unsupported_os",
    }
    risks = [float(f["risk_score"]) for f in findings["items"]]
    assert risks == sorted(risks, reverse=True)

    summary = (await client.get("/api/v1/findings/summary")).json()
    assert summary["open_total"] == 5
    assert summary["open_by_severity"]["critical"] == 1
    assert summary["by_framework"] == {"cyber-essentials-3.3": 4, "iso27001-2022": 5}
    ce = (await client.get("/api/v1/findings", params={"framework": "cyber-essentials-3.3"})).json()
    assert ce["total"] == 4

    mfa = next(f for f in findings["items"] if f["check_id"] == "fake.identity.admin_without_mfa")
    detail = (await client.get(f"/api/v1/findings/{mfa['id']}")).json()
    assert detail["evidence"] == {"admin_roles": ["Administrators"], "mfa_enabled": False}
    assert detail["check"]["remediation"]["summary"]
    assert {(c["framework_id"], c["ref"]) for c in detail["controls"]} == {
        ("cyber-essentials-3.3", "CE.UAC"),
        ("iso27001-2022", "A.8.2"),
        ("iso27001-2022", "A.8.5"),
    }
    assert [e["event"] for e in detail["events"]] == ["new"]

    # Mute it (computed at query time), then revoke the mute.
    mute = await client.post(
        "/api/v1/exceptions",
        json={
            "scope_type": "finding",
            "finding_id": mfa["id"],
            "justification": "Break-glass account, tracked in CHG-42",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
    )
    assert mute.status_code == 201, mute.text
    assert (await client.get("/api/v1/findings")).json()["total"] == 4
    muted = (await client.get("/api/v1/findings", params={"status": "muted"})).json()
    assert [f["id"] for f in muted["items"]] == [mfa["id"]]
    assert (await client.get("/api/v1/findings/summary")).json()["muted"] == 1
    revoked = await client.post(f"/api/v1/exceptions/{mute.json()['id']}/revoke")
    assert revoked.status_code == 200 and revoked.json()["revoked_at"]
    assert (await client.post(f"/api/v1/exceptions/{mute.json()['id']}/revoke")).status_code == 409
    assert (await client.get("/api/v1/findings")).json()["total"] == 5

    # A scan can't be started twice at once.
    first = await client.post("/api/v1/scans", json={"integration_id": integration["id"]})
    assert first.status_code == 202
    again = await client.post("/api/v1/scans", json={"integration_id": integration["id"]})
    assert (again.status_code, again.json()["error"]["code"]) == (409, "scan_in_progress")
    await drain(worker)
    scan = (await client.get(f"/api/v1/scans/{first.json()['id']}")).json()
    assert (scan["status"], scan["stats"]["still_open"]) == ("succeeded", 5)

    # "Fix" everything in the fake cloud: re-verification rescans and resolves all five.
    patched = await client.patch(
        f"/api/v1/integrations/{integration['id']}", json={"config": {"simulate_fixes": ALL_FIXES}}
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["status"] == "verifying"
    await drain(worker)
    assert (await client.get("/api/v1/findings")).json()["total"] == 0
    resolved = (await client.get("/api/v1/findings", params={"status": "resolved"})).json()
    assert resolved["total"] == 5
    events = (await client.get(f"/api/v1/findings/{mfa['id']}")).json()["events"]
    assert events[0]["event"] == "auto_resolved"

    assets = (
        await client.get("/api/v1/assets", params={"resource_type": "fake.compute.vm"})
    ).json()
    web = next(a for a in assets["items"] if a["name"] == "web-frontend")
    web_detail = (await client.get(f"/api/v1/assets/{web['id']}")).json()
    assert web_detail["raw_config"]["user_data"]["redacted"] is True
    assert {(r["direction"], r["type"]) for r in web_detail["relationships"]} == {
        ("out", "attached_to"),
        ("out", "uses_role"),
    }

    audit = (await client.get("/api/v1/audit-log", params={"limit": 200})).json()
    actions = {a["action"] for a in audit["items"]}
    assert {
        "auth.login.succeeded",
        "integration.created",
        "integration.verified",
        "scan.requested",
        "exception.created",
        "exception.revoked",
    } <= actions


async def test_catalogue_endpoints(signed_in: httpx.AsyncClient) -> None:
    checks = (await signed_in.get("/api/v1/checks")).json()
    assert len(checks) >= 5
    frameworks = {f["id"] for f in (await signed_in.get("/api/v1/frameworks")).json()}
    assert {"cyber-essentials-3.3", "iso27001-2022"} <= frameworks
    controls = (await signed_in.get("/api/v1/frameworks/cyber-essentials-3.3/controls")).json()
    assert [c["ref"] for c in controls] == ["CE.FW", "CE.MP", "CE.SC", "CE.SUM", "CE.UAC"]
    assert (await signed_in.get("/api/v1/frameworks/nope/controls")).status_code == 404
    providers = (await signed_in.get("/api/v1/providers")).json()
    assert providers[0]["provider"] == "fake"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"provider": "aws", "name": "x"}, "unknown_provider"),
        (
            {"provider": "fake", "name": "x", "config": {"simulate_fixes": ["rm -rf"]}},
            "invalid_config",
        ),
    ],
)
async def test_integration_input_is_validated(
    signed_in: httpx.AsyncClient, body: dict[str, Any], code: str
) -> None:
    response = await signed_in.post("/api/v1/integrations", json=body)
    assert (response.status_code, response.json()["error"]["code"]) == (422, code)


@pytest.mark.parametrize(
    "expires",
    [timedelta(days=-1), timedelta(days=366)],
)
async def test_exception_expiry_is_bounded(
    signed_in: httpx.AsyncClient, worker: Worker, expires: timedelta
) -> None:
    await _connected_integration(signed_in, worker)
    finding = (await signed_in.get("/api/v1/findings", params={"limit": 1})).json()["items"][0]
    response = await signed_in.post(
        "/api/v1/exceptions",
        json={
            "scope_type": "finding",
            "finding_id": finding["id"],
            "justification": "long enough reason",
            "expires_at": (datetime.now(UTC) + expires).isoformat(),
        },
    )
    assert (response.status_code, response.json()["error"]["code"]) == (422, "invalid_expiry")


async def test_exception_scope_must_match_its_targets(signed_in: httpx.AsyncClient) -> None:
    response = await signed_in.post(
        "/api/v1/exceptions",
        json={
            "scope_type": "check",
            "finding_id": str(uuid4()),
            "justification": "long enough reason",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert response.json()["error"]["code"] == "invalid_scope"


@pytest.mark.parametrize(
    ("role", "method", "path", "body"),
    [
        (Role.VIEWER, "post", "/api/v1/integrations", {"provider": "fake", "name": "x"}),
        (Role.VIEWER, "post", "/api/v1/scans", {"integration_id": str(uuid4())}),
        (Role.ANALYST, "post", "/api/v1/integrations", {"provider": "fake", "name": "x"}),
        (Role.ANALYST, "get", "/api/v1/audit-log", None),
        (Role.VIEWER, "post", "/api/v1/exceptions", {}),
    ],
)
async def test_roles_are_enforced(
    db: Database,
    client: httpx.AsyncClient,
    role: Role,
    method: str,
    path: str,
    body: dict[str, Any] | None,
) -> None:
    user = await make_user(db, role)
    await login(client, user)
    response = await client.request(method.upper(), path, json=body)
    assert response.status_code in {403, 422}
    if response.status_code == 422:  # body validation runs first for some routes
        return
    assert response.json()["error"]["code"] == "forbidden"


async def test_viewer_can_read(db: Database, client: httpx.AsyncClient) -> None:
    await login(client, await make_user(db, Role.VIEWER))
    for path in ("/api/v1/findings", "/api/v1/assets", "/api/v1/integrations", "/api/v1/auth/me"):
        assert (await client.get(path)).status_code == 200


async def test_cross_tenant_ids_are_not_found(
    db: Database, client: httpx.AsyncClient, admin: User, worker: Worker
) -> None:
    await login(client, admin)
    integration = await _connected_integration(client, worker)
    finding = (await client.get("/api/v1/findings", params={"limit": 1})).json()["items"][0]
    asset = (await client.get("/api/v1/assets", params={"limit": 1})).json()["items"][0]
    scan = (await client.get("/api/v1/scans", params={"limit": 1})).json()["items"][0]

    client.cookies.clear()
    await login(client, await make_user(db))
    for path in (
        f"/api/v1/integrations/{integration['id']}",
        f"/api/v1/findings/{finding['id']}",
        f"/api/v1/assets/{asset['id']}",
        f"/api/v1/scans/{scan['id']}",
    ):
        assert (await client.get(path)).status_code == 404, path
    for method, path, body in (
        ("PATCH", f"/api/v1/integrations/{integration['id']}", {"name": "pwned"}),
        ("DELETE", f"/api/v1/integrations/{integration['id']}", None),
        ("POST", f"/api/v1/integrations/{integration['id']}/test", None),
        ("POST", "/api/v1/scans", {"integration_id": integration["id"]}),
    ):
        response = await client.request(method, path, json=body)
        assert response.status_code == 404, (method, path)
    exception = await client.post(
        "/api/v1/exceptions",
        json={
            "scope_type": "finding",
            "finding_id": finding["id"],
            "justification": "trying another tenant",
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    assert exception.status_code == 404
    assert (await client.get("/api/v1/findings")).json()["total"] == 0


async def test_delete_integration_hides_its_findings_and_assets(
    signed_in: httpx.AsyncClient, worker: Worker
) -> None:
    integration = await _connected_integration(signed_in, worker)
    asset = (await signed_in.get("/api/v1/assets", params={"limit": 1})).json()["items"][0]
    assert (await signed_in.delete(f"/api/v1/integrations/{integration['id']}")).status_code == 204
    assert (await signed_in.get(f"/api/v1/integrations/{integration['id']}")).status_code == 404
    assert (await signed_in.get("/api/v1/findings")).json()["total"] == 0
    listed = await signed_in.get("/api/v1/assets", params={"include_deleted": True})
    assert listed.json()["total"] == 0
    assert (await signed_in.get(f"/api/v1/assets/{asset['id']}")).status_code == 404


async def test_integration_updates_are_audited_with_before_and_after(
    db: Database, signed_in: httpx.AsyncClient, admin: User, worker: Worker
) -> None:
    integration = await _connected_integration(signed_in, worker)
    response = await signed_in.patch(
        f"/api/v1/integrations/{integration['id']}",
        json={"name": "Renamed", "config": {"simulate_fixes": ["encrypt_bucket"]}},
    )
    assert response.status_code == 200
    async with tenant_scope(db.factory("skyline_api"), admin.tenant.id) as session:
        details = (
            await session.execute(
                select(AuditLog.details).where(AuditLog.action == "integration.updated")
            )
        ).scalar_one()
    assert details["changes"]["name"] == {"before": "Demo", "after": "Renamed"}
    assert details["changes"]["config"]["after"]["simulate_fixes"] == ["encrypt_bucket"]


async def test_demo_provider_needs_to_be_enabled(db: Database, admin: User) -> None:
    from api_helpers import api_settings

    from skyline_api.app import create_app

    settings = api_settings(db, demo_provider_enabled=False)
    app = create_app(settings, make_services(db, settings))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
    ) as client:
        await login(client, admin)
        assert (await client.get("/api/v1/providers")).json() == []
        created = await client.post("/api/v1/integrations", json={"provider": "fake", "name": "x"})
        assert (created.status_code, created.json()["error"]["code"]) == (
            422,
            "unsupported_provider",
        )


async def test_read_only_transactions_reject_writes(db: Database, admin: User) -> None:
    from api_helpers import api_settings

    svc = make_services(db, api_settings(db))
    principal = Principal(
        user_id=admin.tenant.admin_id,
        tenant_id=admin.tenant.id,
        role="admin",
        session_id=uuid4(),
        token_hash=b"x" * 32,
        must_change_password=False,
        ip=None,
    )
    with pytest.raises(DBAPIError, match="read-only transaction"):
        async with TenantDb(svc, principal, read_only=True).transaction() as session:
            await session.execute(
                insert(Integration).values(
                    id=uuid4(),
                    tenant_id=admin.tenant.id,
                    provider="fake",
                    name="x",
                    status="verifying",
                )
            )


async def test_repeated_verify_requests_queue_one_job(
    db: Database, signed_in: httpx.AsyncClient, admin: User, worker: Worker
) -> None:
    from skyline_core.db.models import Job

    integration = await _connected_integration(signed_in, worker)
    for _ in range(5):
        response = await signed_in.post(f"/api/v1/integrations/{integration['id']}/test")
        assert response.status_code == 202
    async with tenant_scope(db.factory("skyline_worker"), admin.tenant.id) as session:
        queued = (
            await session.execute(
                select(Job.id).where(
                    Job.integration_id == integration["id"],
                    Job.kind == "verify_integration",
                    Job.status == "queued",
                )
            )
        ).all()
    assert len(queued) == 1


async def test_deleting_an_integration_removes_its_credential(
    db: Database, signed_in: httpx.AsyncClient, admin: User, worker: Worker
) -> None:
    from skyline_core.db.models import Secret

    integration = await _connected_integration(signed_in, worker)
    async with tenant_scope(db.factory("skyline_api"), admin.tenant.id) as session:
        before = (
            await session.execute(
                select(Secret.id).where(Secret.purpose == "integration_credential")
            )
        ).all()
    assert (await signed_in.delete(f"/api/v1/integrations/{integration['id']}")).status_code == 204
    async with tenant_scope(db.factory("skyline_api"), admin.tenant.id) as session:
        after = (
            await session.execute(
                select(Secret.id).where(Secret.purpose == "integration_credential")
            )
        ).all()
    assert len(after) == len(before) - 1
