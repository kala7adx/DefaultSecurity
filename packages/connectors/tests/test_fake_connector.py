from __future__ import annotations

import secrets
from collections import Counter

import pytest
from pydantic import SecretStr, ValidationError

from skyline_connectors.base import ApiNotAllowedError, AuthenticationError, Scope
from skyline_connectors.fake.connector import FakeConnector
from skyline_connectors.fake.models import FakeConfig, FakeCredentials
from skyline_connectors.gateway import GuardedGateway
from skyline_connectors.registry import UnknownProviderError, get_spec
from skyline_connectors.runner import ScopeResult, collect_all

HMAC_KEY = b"k" * 32


def _creds() -> FakeCredentials:
    return FakeCredentials(api_key=SecretStr(secrets.token_urlsafe(32)))


async def _collect(config: FakeConfig) -> tuple[list[ScopeResult], GuardedGateway]:
    spec = get_spec("fake")
    connector, gateway = spec.build(config, _creds())
    assert (await connector.validate_credentials()).ok
    scopes = await connector.discover_scopes()
    results = await collect_all(
        connector, scopes, provider="fake", rules=spec.redaction, hmac_key=HMAC_KEY
    )
    return results, gateway


async def test_collects_the_seeded_company() -> None:
    results, gateway = await _collect(FakeConfig())
    assert [r.scope.id for r in results] == ["fake-acct-001", "fake-north-1", "fake-south-1"]
    assert all(r.ok and r.rejected == 0 for r in results)
    assets = [a for r in results for a in r.assets]
    assert Counter(a.resource_type for a in assets) == {
        "fake.identity.role": 3,
        "fake.identity.user": 3,
        "fake.compute.vm": 2,
        "fake.network.security_group": 2,
        "fake.storage.bucket": 2,
    }
    edges = {
        (e.type, e.src_native_id.rsplit("/", 1)[1], e.dst_native_id.rsplit("/", 1)[1])
        for r in results
        for e in r.relationships
    }
    assert ("attached_to", "vm-web-01", "sg-web-open") in edges
    assert ("uses_role", "vm-web-01", "role-web") in edges
    assert ("member_of", "alice.admin", "role-admin") in edges
    # Every call the connector made is in its allowlist (fixture run ⊆ allowlist).
    assert set(gateway.calls) <= FakeConnector.api_allowlist
    # Pagination was exercised (one VM per page).
    assert (
        gateway.calls.count(
            next(c for c in FakeConnector.api_allowlist if c.operation == "DescribeInstances")
        )
        >= 2
    )


async def test_secret_bearing_fields_are_redacted() -> None:
    results, _ = await _collect(FakeConfig())
    web = next(a for r in results for a in r.assets if a.native_id.endswith("vm-web-01"))
    marker = web.raw_config["user_data"]
    assert isinstance(marker, dict)
    assert marker["redacted"] is True
    assert "db-password-file" not in str(web.raw_config)
    assert web.tags == {"env": "prod", "team": "web"}


async def test_output_is_deterministic() -> None:
    first, _ = await _collect(FakeConfig())
    second, _ = await _collect(FakeConfig())
    assert [a.config_hash for r in first for a in r.assets] == [
        a.config_hash for r in second for a in r.assets
    ]


async def test_simulated_fixes_change_the_data() -> None:
    results, _ = await _collect(
        FakeConfig(
            simulate_fixes=[
                "remove_public_ip",
                "close_admin_ports",
                "encrypt_bucket",
                "enable_mfa",
                "upgrade_os",
            ]
        )
    )
    by_id = {a.native_id.rsplit("/", 1)[1]: a.raw_config for r in results for a in r.assets}
    assert by_id["vm-web-01"]["public_ip"] is None
    assert by_id["vm-web-01"]["os"] == {
        "name": "FakeOS",
        "version": "24.04",
        "end_of_support": "2034-04-30",
    }
    ingress = by_id["sg-web-open"]["ingress"]
    assert isinstance(ingress, list)
    assert {r["from_port"] for r in ingress if isinstance(r, dict)} == {443}
    assert by_id["fake-customer-exports"]["encryption"] == {"algorithm": "AES256"}
    assert by_id["alice.admin"]["mfa_enabled"] is True


async def test_failing_scopes_are_isolated() -> None:
    results, _ = await _collect(FakeConfig(fail_scopes=["fake-north-1"]))
    by_scope = {r.scope.id: r for r in results}
    assert not by_scope["fake-north-1"].ok
    assert by_scope["fake-north-1"].error == "region fake-north-1 is unavailable (simulated)"
    assert by_scope["fake-north-1"].assets == []
    assert by_scope["fake-south-1"].ok
    assert by_scope["fake-acct-001"].ok


async def test_identity_scope_failure() -> None:
    results, _ = await _collect(FakeConfig(fail_scopes=["fake-acct-001"]))
    assert not next(r for r in results if r.scope.id == "fake-acct-001").ok


async def test_bad_credentials_are_rejected() -> None:
    spec = get_spec("fake")
    creds = FakeCredentials.model_construct(api_key=SecretStr("short"))
    connector, _ = spec.build(FakeConfig(), creds)
    with pytest.raises(AuthenticationError):
        await connector.validate_credentials()


async def test_unknown_region_scope() -> None:
    connector, _ = get_spec("fake").build(FakeConfig(), _creds())
    results = await collect_all(
        connector,
        [Scope(kind="region", id="nowhere-1")],
        provider="fake",
        rules=get_spec("fake").redaction,
        hmac_key=HMAC_KEY,
    )
    assert results[0].error == "unknown region"


def test_config_is_strict() -> None:
    with pytest.raises(ValidationError):
        FakeConfig(simulate_fixes=["drop_database"])  # type: ignore[list-item]
    with pytest.raises(ValidationError):
        FakeConfig.model_validate({"simulate_fixes": [], "extra": 1})
    with pytest.raises(ValidationError):
        FakeCredentials(api_key=SecretStr("short"))


def test_unknown_provider() -> None:
    with pytest.raises(UnknownProviderError):
        get_spec("aws")


async def test_transport_rejects_unknown_calls_even_if_gateway_were_bypassed() -> None:
    from skyline_connectors.base import ApiCall
    from skyline_connectors.fake.transport import FakeTransport

    transport = FakeTransport(FakeConfig(), _creds())
    with pytest.raises(Exception, match="unknown"):
        await transport.send(ApiCall("fake", "DeleteBucket"), {})
    with pytest.raises(Exception, match="unknown"):
        await transport.send(ApiCall("other", "ListRegions"), {})
    gateway = GuardedGateway(transport, frozenset())
    with pytest.raises(ApiNotAllowedError):
        await gateway.call(ApiCall("fake", "ListRegions"))
