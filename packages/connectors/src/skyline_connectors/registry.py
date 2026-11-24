"""Static connector registry for the worker (ARCHITECTURE §5).

Connectors are registered here by name; nothing is ever imported from a string stored in the
database or a YAML file. Every allowlist is validated as read-only when the registry is built,
so declaring a write API fails at import time.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from pydantic import BaseModel

from skyline_connectors.allowlist import AllowlistStyle, validate_allowlist
from skyline_connectors.base import ApiCall, ApiGateway, Connector
from skyline_connectors.catalog import PROVIDERS, ProviderInfo
from skyline_connectors.fake.connector import FakeConnector
from skyline_connectors.fake.models import FakeConfig, FakeCredentials
from skyline_connectors.fake.transport import FakeTransport
from skyline_connectors.gateway import GatewayLimits, GuardedGateway, Transport
from skyline_core.redaction import RedactionRules

#: ``(config, credentials, validated allowlist) -> transport``.
type TransportFactory = Callable[[BaseModel, BaseModel, frozenset[ApiCall]], Transport]


class ConnectorClass(Protocol):
    """A connector type: class-level allowlist plus a gateway-only constructor."""

    provider: str
    api_allowlist: frozenset[ApiCall]

    def __call__(self, *, gateway: ApiGateway) -> Connector: ...


@dataclass(frozen=True, slots=True)
class ConnectorSpec:
    info: ProviderInfo
    connector: ConnectorClass
    credential_model: type[BaseModel]
    transport_factory: TransportFactory
    allowlist_style: AllowlistStyle
    allowlist: frozenset[ApiCall]
    redaction: RedactionRules

    def build(
        self, config: BaseModel, credentials: BaseModel, limits: GatewayLimits | None = None
    ) -> tuple[Connector, GuardedGateway]:
        """Wire transport → guarded gateway → connector. The connector never sees the
        transport, and both the gateway and the transport enforce the validated allowlist."""
        transport = self.transport_factory(config, credentials, self.allowlist)
        gateway = GuardedGateway(transport, self.allowlist, limits)
        return self.connector(gateway=gateway), gateway


def _fake_transport(
    config: BaseModel, credentials: BaseModel, allowlist: frozenset[ApiCall]
) -> Transport:
    assert isinstance(config, FakeConfig)  # noqa: S101 - spec pairs models with factories
    assert isinstance(credentials, FakeCredentials)  # noqa: S101
    return FakeTransport(config, credentials, allowlist)


def make_spec(
    *,
    info: ProviderInfo,
    connector: ConnectorClass,
    credential_model: type[BaseModel],
    transport_factory: TransportFactory,
    allowlist_style: AllowlistStyle,
    redaction: RedactionRules,
) -> ConnectorSpec:
    """Build a spec, validating the connector's allowlist as read-only."""
    if connector.provider != info.provider:
        msg = "connector and provider info disagree on the provider name"
        raise ValueError(msg)
    return ConnectorSpec(
        info=info,
        connector=connector,
        credential_model=credential_model,
        transport_factory=transport_factory,
        allowlist_style=allowlist_style,
        allowlist=validate_allowlist(connector.api_allowlist, allowlist_style),
        redaction=redaction,
    )


REGISTRY: Final[Mapping[str, ConnectorSpec]] = {
    "fake": make_spec(
        info=PROVIDERS["fake"],
        connector=FakeConnector,
        credential_model=FakeCredentials,
        transport_factory=_fake_transport,
        allowlist_style=AllowlistStyle.SDK,
        redaction=RedactionRules.for_keys(["user_data"]),
    ),
}


class UnknownProviderError(LookupError):
    """No connector is registered under that provider name."""


def get_spec(provider: str) -> ConnectorSpec:
    try:
        return REGISTRY[provider]
    except KeyError:
        raise UnknownProviderError(provider) from None
