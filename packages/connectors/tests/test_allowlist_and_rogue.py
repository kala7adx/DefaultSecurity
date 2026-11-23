"""Read-only enforcement (CLAUDE.md rule 1, ADR-0005): rogue connectors must be rejected."""

from __future__ import annotations

import ast
from collections.abc import AsyncIterator, Sequence
from importlib import resources
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import BaseModel

from skyline_connectors.allowlist import AllowlistStyle, is_read_only, validate_allowlist
from skyline_connectors.base import (
    ApiCall,
    ApiGateway,
    ApiNotAllowedError,
    AssetRecord,
    ReadOnlyViolationError,
    RelationshipRecord,
    Scope,
    ValidationResult,
)
from skyline_connectors.catalog import PROVIDERS, CredentialMode, ProviderInfo
from skyline_connectors.gateway import GuardedGateway
from skyline_connectors.registry import REGISTRY, make_spec
from skyline_core.redaction import RedactionRules
from skyline_core.types import JSON


@pytest.mark.parametrize(
    "operation",
    ["DescribeInstances", "ListBuckets", "GetBucketEncryption", "GetCallerIdentity"],
)
def test_sdk_read_operations_are_allowed(operation: str) -> None:
    assert is_read_only(ApiCall("ec2", operation), AllowlistStyle.SDK)


@pytest.mark.parametrize(
    "operation",
    [
        "DeleteBucket",
        "PutBucketPolicy",
        "CreateUser",
        "UpdateFunctionConfiguration",
        "AttachRolePolicy",
        "TerminateInstances",
        "Getaway",  # read prefix must be followed by an upper-case word
        "describeInstances",
        "List",
        "GetX; DeleteY",
    ],
)
def test_sdk_write_operations_are_rejected(operation: str) -> None:
    assert not is_read_only(ApiCall("ec2", operation), AllowlistStyle.SDK)


@pytest.mark.parametrize("operation", ["GET /v1.0/users", "GET /v1.0/users/{id}/authentication"])
def test_http_get_is_allowed(operation: str) -> None:
    assert is_read_only(ApiCall("graph", operation), AllowlistStyle.HTTP)


@pytest.mark.parametrize(
    "operation",
    ["POST /v1.0/users", "DELETE /v1.0/users/{id}", "get /x", "GET http://evil/x", "PATCH /a"],
)
def test_http_non_get_is_rejected(operation: str) -> None:
    assert not is_read_only(ApiCall("graph", operation), AllowlistStyle.HTTP)


def test_bad_service_names_are_rejected() -> None:
    assert not is_read_only(ApiCall("EC2!", "DescribeInstances"), AllowlistStyle.SDK)


def test_validate_allowlist_names_offenders() -> None:
    with pytest.raises(ReadOnlyViolationError, match=r"s3:DeleteBucket"):
        validate_allowlist(
            [ApiCall("s3", "ListBuckets"), ApiCall("s3", "DeleteBucket")], AllowlistStyle.SDK
        )
    with pytest.raises(ReadOnlyViolationError):
        validate_allowlist([], AllowlistStyle.SDK)


class _RogueWriter:
    """Declares a write API in its allowlist: must not be registrable."""

    provider: ClassVar[str] = "fake"
    api_allowlist: ClassVar[frozenset[ApiCall]] = frozenset(
        {ApiCall("fake", "ListRegions"), ApiCall("fake", "DeleteEverything")}
    )

    def __init__(self, *, gateway: ApiGateway) -> None:
        self._gw = gateway

    async def validate_credentials(self) -> ValidationResult:
        return ValidationResult(ok=True)

    async def discover_scopes(self) -> Sequence[Scope]:
        return []

    async def collect(self, scope: Scope) -> AsyncIterator[AssetRecord | RelationshipRecord]:
        del scope
        if False:  # pragma: no cover - generator with no items
            yield


class _Transport:
    async def send(self, api: ApiCall, params: dict[str, JSON]) -> dict[str, JSON]:
        del params
        return {"called": str(api)}


def test_registering_a_connector_with_a_write_api_fails() -> None:
    info = ProviderInfo("fake", "Rogue", "", BaseModel, CredentialMode.GENERATED)
    with pytest.raises(ReadOnlyViolationError, match="DeleteEverything"):
        make_spec(
            info=info,
            connector=_RogueWriter,
            credential_model=BaseModel,
            transport_factory=lambda _c, _k: _Transport(),
            allowlist_style=AllowlistStyle.SDK,
            redaction=RedactionRules(),
        )


async def test_a_connector_calling_outside_its_allowlist_is_stopped() -> None:
    gateway = GuardedGateway(_Transport(), frozenset({ApiCall("fake", "ListRegions")}))
    with pytest.raises(ApiNotAllowedError, match="fake:PutObject"):
        await gateway.call(ApiCall("fake", "PutObject"))
    # Same operation name under another service is a different call.
    with pytest.raises(ApiNotAllowedError):
        await gateway.call(ApiCall("s3", "ListRegions"))
    assert gateway.calls == []


def test_every_registered_connector_is_read_only() -> None:
    assert set(REGISTRY) == set(PROVIDERS)
    for spec in REGISTRY.values():
        assert spec.allowlist == spec.connector.api_allowlist
        assert all(is_read_only(api, spec.allowlist_style) for api in spec.allowlist)


def test_provider_name_mismatch_is_rejected() -> None:
    info = ProviderInfo("other", "x", "", BaseModel, CredentialMode.GENERATED)
    with pytest.raises(ValueError, match="disagree"):
        make_spec(
            info=info,
            connector=_RogueWriter,
            credential_model=BaseModel,
            transport_factory=lambda _c, _k: _Transport(),
            allowlist_style=AllowlistStyle.SDK,
            redaction=RedactionRules(),
        )


# ----------------------------------------------------------------- static import rules

#: Modules that talk to the network. Only transport modules may import them.
NETWORK_MODULES = {
    "boto3",
    "botocore",
    "aiobotocore",
    "httpx",
    "requests",
    "urllib",
    "urllib3",
    "aiohttp",
    "socket",
    "http",
    "ssl",
    "msgraph",
    "msal",
    "azure",
    "google",
    "googleapiclient",
    "subprocess",
}


def _imported_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def _package_files() -> list[Path]:
    root = Path(str(resources.files("skyline_connectors")))
    return sorted(root.rglob("*.py"))


def test_only_transport_modules_import_network_libraries() -> None:
    offenders = []
    for path in _package_files():
        if path.name == "transport.py":
            continue
        bad = _imported_roots(path.read_text(encoding="utf-8")) & NETWORK_MODULES
        if bad:
            offenders.append(f"{path.name}: {sorted(bad)}")
    assert offenders == []


def test_connectors_never_use_dynamic_imports_or_eval() -> None:
    for path in _package_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "__import__", "compile"}, path
            if isinstance(node, ast.Attribute):
                assert node.attr != "import_module", path


def test_connectors_never_import_checks() -> None:
    for path in _package_files():
        assert "skyline_checks" not in _imported_roots(path.read_text(encoding="utf-8")), path
