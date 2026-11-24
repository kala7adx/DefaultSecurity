"""Read-only enforcement (CLAUDE.md rule 1, ADR-0005): rogue connectors must be rejected."""

from __future__ import annotations

import ast
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from importlib import resources
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import BaseModel

from skyline_connectors.allowlist import (
    DENIED_SDK_OPERATIONS,
    AllowlistStyle,
    is_read_only,
    validate_allowlist,
)
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

_SDK_READ_SHAPE = re.compile(r"^(Describe|List|Get|BatchGet)[A-Z]")


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


@pytest.mark.parametrize("operation", sorted(DENIED_SDK_OPERATIONS))
def test_data_plane_and_credential_reads_are_rejected(operation: str) -> None:
    assert _SDK_READ_SHAPE.match(operation), "deny list entries must look like reads"
    assert not is_read_only(ApiCall("any", operation), AllowlistStyle.SDK)


@pytest.mark.parametrize(
    "operation",
    [
        "GET /v1.0/users/{id}/messages",
        "GET /v1.0/me/mailFolders/inbox",
        "GET /v1.0/drives/{id}/items/{id}/content",
        "GET /v1.0/users/{id}/photo/$value",
        "GET /v1.0/teams/{id}/channels/{id}/messages",
        "GET /v1.0/users/{id}/events",
        "GET /v1.0/users/{id}/calendarView",
        "GET /v1.0/chats",
        "GET /v1.0/users/../admin",
        "GET /v1.0/users/..",
    ],
)
def test_http_content_and_traversal_paths_are_rejected(operation: str) -> None:
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
        nothing: list[AssetRecord] = []
        for record in nothing:  # an async generator with no items
            yield record


class _Transport:
    async def send(self, api: ApiCall, params: Mapping[str, JSON]) -> Mapping[str, JSON]:
        del params
        return {"called": str(api)}


def test_registering_a_connector_with_a_write_api_fails() -> None:
    info = ProviderInfo("fake", "Rogue", "", BaseModel, CredentialMode.GENERATED)
    with pytest.raises(ReadOnlyViolationError, match="DeleteEverything"):
        make_spec(
            info=info,
            connector=_RogueWriter,
            credential_model=BaseModel,
            transport_factory=lambda _c, _k, _a: _Transport(),
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
            transport_factory=lambda _c, _k, _a: _Transport(),
            allowlist_style=AllowlistStyle.SDK,
            redaction=RedactionRules(),
        )


# ----------------------------------------------------------------- static rules (tripwire)
#
# ADR-0005 layer 4. Python can't isolate code inside one process, so these rules are a
# tripwire that makes a non-read-only connector stand out in review, not a sandbox. The hard
# boundaries are the customer-side read-only role with explicit Denies (layer 1) and the
# runtime guard in the gateway and transport (layer 3).

#: ``from <module> import <name>`` that connector code may use: an allowlist of *names*, so a
#: new capability (``asyncio.open_connection``, ``pydantic.ImportString`` ...) has to be added
#: here on purpose. ``"*"`` = any name except the banned ones below.
ALLOWED_FROM_IMPORTS: dict[str, set[str] | str] = {
    "__future__": {"annotations"},
    "asyncio": {"Semaphore", "gather", "sleep", "timeout", "Event", "Lock", "wait_for"},
    "collections.abc": "*",
    "dataclasses": {"dataclass", "field", "replace"},
    "enum": {"Enum", "StrEnum", "IntEnum"},
    "typing": {"Any", "ClassVar", "Final", "Literal", "Protocol", "cast", "TypeVar", "NamedTuple"},
    "pydantic": {
        "BaseModel",
        "ConfigDict",
        "Field",
        "SecretStr",
        "field_validator",
        "model_validator",
    },
    "skyline_core.logging": {"get_logger"},
    "skyline_core.redaction": "*",
    "skyline_core.types": "*",
    "skyline_connectors.allowlist": "*",
    "skyline_connectors.base": "*",
    "skyline_connectors.catalog": "*",
    "skyline_connectors.fake.connector": "*",
    "skyline_connectors.fake.dataset": "*",
    "skyline_connectors.fake.models": "*",
    "skyline_connectors.fake.transport": "*",
    "skyline_connectors.gateway": "*",
}
#: ``import <module>``: only pure-computation modules.
ALLOWED_MODULE_IMPORTS = {"re", "json", "math", "copy", "random"}
#: Internal modules only the registry may import: connectors never see transports, gateways
#: or the runner (no ``REGISTRY["fake"].transport_factory(...)`` from a connector).
REGISTRY_ONLY = {
    "skyline_connectors.registry",
    "skyline_connectors.gateway",
    "skyline_connectors.runner",
    "skyline_connectors.fake.transport",
}
#: Names that reach code, modules or objects indirectly.
BANNED_NAMES = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "vars",
    "globals",
    "locals",
    "open",
    "breakpoint",
    "input",
    "importlib",
    "get_type_hints",
    "ImportString",
    "TypeAdapter",
    "builtins",
}
ALLOWED_DUNDER_ATTRIBUTES = {"__init__", "__name__"}
#: Frame and code objects lead to builtins and globals without naming them.
BANNED_ATTRIBUTES = {
    "gi_frame",
    "cr_frame",
    "ag_frame",
    "tb_frame",
    "f_globals",
    "f_builtins",
    "f_locals",
    "f_back",
    "gi_code",
    "cr_code",
}

#: Network SDKs: only transport modules may import these (none exist in Phase 0).
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
}


def _import_violations(node: ast.AST, *, filename: str, transport: bool) -> list[str]:
    found: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            root = alias.name.split(".")[0]
            if transport and root in NETWORK_MODULES:
                continue
            if alias.name not in ALLOWED_MODULE_IMPORTS:
                found.append(f"import {alias.name}")
    elif isinstance(node, ast.ImportFrom):
        found += _from_import_violations(node, filename=filename, transport=transport)
    return found


def _from_import_violations(node: ast.ImportFrom, *, filename: str, transport: bool) -> list[str]:
    module = node.module or ""
    names = {a.name for a in node.names}
    if node.level != 0:
        return [f"relative import from {module}"]
    if transport and module.split(".")[0] in NETWORK_MODULES:
        return []
    if module in REGISTRY_ONLY and filename != "registry.py":
        return [f"from {module} (registry only)"]
    found = [f"from {module} import {sorted(names & BANNED_NAMES)}"] if names & BANNED_NAMES else []
    allowed = ALLOWED_FROM_IMPORTS.get(module)
    if allowed is None:
        found.append(f"from {module}")
    elif isinstance(allowed, set) and not names <= allowed:
        found.append(f"from {module} import {sorted(names - allowed)}")
    return found


def _attribute_violations(node: ast.Attribute) -> list[str]:
    found: list[str] = []
    owner = node.value.id if isinstance(node.value, ast.Name) else None
    if node.attr.startswith("__"):
        if node.attr not in ALLOWED_DUNDER_ATTRIBUTES:
            found.append(f"dunder .{node.attr}")
    elif node.attr.startswith("_") and owner not in {"self", "cls"}:
        found.append(f"private .{node.attr} of {owner or 'an expression'}")
    if owner in {"object", "type", "asyncio", "os", "sys"}:
        found.append(f"{owner}.{node.attr}")
    if node.attr in BANNED_NAMES and owner not in ALLOWED_MODULE_IMPORTS:
        found.append(f"attribute .{node.attr}")  # re.compile is fine
    if node.attr in BANNED_ATTRIBUTES:
        found.append(f"frame access .{node.attr}")
    return found


def find_violations(source: str, *, filename: str = "module.py") -> list[str]:
    """Every rule break in one connector module (the rules above)."""
    transport = filename == "transport.py"
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        found += _import_violations(node, filename=filename, transport=transport)
        if isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            found.append(f"name {node.id}")
        elif isinstance(node, ast.Attribute):
            found += _attribute_violations(node)
        elif isinstance(node, ast.MatchClass):
            # `case object(_transport=t)` reads attributes by name, like getattr.
            cls = node.cls.id if isinstance(node.cls, ast.Name) else None
            if cls in {"object", "type"} or any(a.startswith("_") for a in node.kwd_attrs):
                found.append(f"match class pattern on {cls} {node.kwd_attrs}")
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("__")
        ):
            found.append(f"dunder string {node.value[:20]!r}")  # d['__builtins__']
    return [f"{filename}: {v}" for v in found]


def _package_files() -> list[Path]:
    root = Path(str(resources.files("skyline_connectors")))
    return sorted(root.rglob("*.py"))


def test_connector_package_follows_the_static_rules() -> None:
    offenders = [
        v
        for path in _package_files()
        for v in find_violations(path.read_text(encoding="utf-8"), filename=path.name)
    ]
    assert offenders == []


@pytest.mark.parametrize(
    "source",
    [
        "import boto3",
        "import socket",
        "import subprocess",
        "import os",
        "import asyncio\nasyncio.open_connection('h', 1)",
        "from asyncio import open_connection",
        "from asyncio import create_subprocess_exec",
        "import importlib",
        "from importlib import import_module",
        "__import__('boto3')",
        "eval('1')",
        "exec('x=1')",
        "getattr(object(), 'x')",
        "open('/etc/passwd')",
        "from pydantic import TypeAdapter, ImportString",
        "from typing import get_type_hints",
        "from skyline_core.db.engine import create_engine",
        "from skyline_core.settings import CoreSettings",
        "from skyline_connectors.registry import REGISTRY",
        "from skyline_connectors.gateway import GuardedGateway",
        "from skyline_connectors.fake.transport import FakeTransport",
        "def f(gw):\n    return gw._transport",
        "def f(gw):\n    return gw.__getstate__()['_transport']",
        "def f(t):\n    object.__setattr__(t, '_allowlist', set())",
        "def f(x):\n    return type(x).__mro__",
        "from . import base",
        "import builtins",
        "def f():\n    return (x for x in ()).gi_frame.f_builtins",
        "def f(c):\n    return c.cr_frame.f_globals",
        "def f(gw):\n    match gw:\n        case object(_transport=t):\n            return t",
        "def f(gw, G):\n    match gw:\n        case G(_violations=v):\n            return v",
        "def f(d):\n    return d['__builtins__']",
        "def f(gw):\n    gw._violations.clear()",
    ],
)
def test_the_rules_catch_each_known_bypass(source: str) -> None:
    assert find_violations(source, filename="rogue.py"), source


def test_transports_may_import_network_sdks_but_nothing_else_new() -> None:
    assert (
        find_violations("import httpx\nfrom botocore import config", filename="transport.py") == []
    )
    assert find_violations("import subprocess", filename="transport.py")


def test_connectors_never_import_checks() -> None:
    for path in _package_files():
        assert "skyline_checks" not in path.read_text(encoding="utf-8"), path
