"""Connector plugin interface (ARCHITECTURE §5, ADR-0005).

A connector discovers scopes (accounts, regions, subscriptions …) and yields asset and
relationship records for each. It reaches its provider **only** through the injected
:class:`ApiGateway`, which refuses any call outside the connector's read-only allowlist.
Connectors never write to the database and never import checks.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from skyline_core.types import JSON

ScopeKind = Literal[
    "account",
    "region",
    "organization",
    "org_unit",
    "subscription",
    "project",
    "tenant",
    "domain",
]


@dataclass(frozen=True, slots=True)
class ApiCall:
    """One provider API operation, e.g. ``ApiCall("ec2", "DescribeInstances")`` or
    ``ApiCall("graph", "GET /v1.0/users")``."""

    service: str
    operation: str

    def __str__(self) -> str:
        return f"{self.service}:{self.operation}"


@dataclass(frozen=True, slots=True)
class Scope:
    """A unit of collection that succeeds or fails independently."""

    kind: ScopeKind
    id: str
    parent_id: str | None = None


@dataclass(frozen=True, slots=True)
class AssetRecord:
    """A resource as the connector saw it. The runner validates, caps and redacts it."""

    resource_type: str
    native_id: str
    name: str | None
    account_id: str | None
    region: str | None
    tags: Mapping[str, str]
    raw_config: Mapping[str, JSON]
    scope_id: str


@dataclass(frozen=True, slots=True)
class RelationshipRecord:
    """A directed edge between two assets, by native ID."""

    src_native_id: str
    dst_native_id: str
    type: str
    properties: Mapping[str, JSON] = field(default_factory=dict)


class ValidationResult(BaseModel):
    """Outcome of a credential check. ``detail`` is sanitised and safe to show users."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ok: bool
    identity: str | None = None
    missing_permissions: list[str] = Field(default_factory=list)
    detail: str = ""


class ApiGateway(Protocol):
    """The ONLY way a connector reaches a provider (see :mod:`skyline_connectors.gateway`)."""

    async def call(self, api: ApiCall, /, **params: JSON) -> Mapping[str, JSON]: ...

    def paginate(self, api: ApiCall, /, **params: JSON) -> AsyncIterator[Mapping[str, JSON]]: ...


class Connector(Protocol):
    """What every provider connector implements."""

    provider: ClassVar[str]
    api_allowlist: ClassVar[frozenset[ApiCall]]

    async def validate_credentials(self) -> ValidationResult: ...

    async def discover_scopes(self) -> Sequence[Scope]: ...

    def collect(self, scope: Scope) -> AsyncIterator[AssetRecord | RelationshipRecord]: ...


# --------------------------------------------------------------------------- errors


class ConnectorError(Exception):
    """Base class for expected connector failures. ``safe_message`` may be shown to users."""

    safe_message: str = "the provider request failed"

    def __init__(self, safe_message: str | None = None) -> None:
        if safe_message is not None:
            self.safe_message = safe_message
        super().__init__(self.safe_message)


class ReadOnlyGuardError(Exception):
    """The read-only guard stopped a call. Deliberately **not** a :class:`ConnectorError`:
    connector code that catches ``ConnectorError`` (say, AccessDenied on one bucket) must
    not be able to swallow it. The gateway also records every violation, so a violation is
    seen even if a connector catches ``Exception``."""

    safe_message: str = "the connector attempted an API call outside its read-only allowlist"


class ApiNotAllowedError(ReadOnlyGuardError):
    """A connector tried to call an API that is not in its read-only allowlist."""

    def __init__(self, api: ApiCall) -> None:
        super().__init__(f"API call not allowed: {api}")
        self.api = api


class ReadOnlyViolationError(ConnectorError):
    """An allowlist entry is not a read-only operation. Raised at registration time."""


class TransientError(ConnectorError):
    """A retryable provider failure (5xx, connection reset, timeout)."""

    safe_message = "the provider was temporarily unavailable"


class ThrottledError(TransientError):
    """The provider asked us to slow down."""

    safe_message = "the provider throttled the request"

    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__()
        self.retry_after = retry_after


class AuthenticationError(ConnectorError):
    """Credentials were rejected or access was lost."""

    safe_message = "the provider rejected the credentials"


class ResponseTooLargeError(ConnectorError):
    """A response exceeded the gateway's size cap."""

    safe_message = "the provider returned more data than allowed"


class PaginationLimitError(ConnectorError):
    """A listing exceeded the page cap or repeated a page token."""

    safe_message = "the provider listing did not terminate within limits"


class ScopeError(ConnectorError):
    """A whole scope could not be collected (e.g. a region is disabled)."""
