"""Provider metadata and config models, safe for the API to import.

This module must never import connector implementations or transports: the API process holds
no cloud credentials and must not contain collection code (ARCHITECTURE §2). An import test
enforces that importing the API does not load any transport module.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from pydantic import BaseModel

from skyline_connectors.fake.models import FakeConfig


class CredentialMode(StrEnum):
    """How an integration gets its credential."""

    #: Skyline generates a placeholder credential (the fake connector only).
    GENERATED = "generated"


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    provider: str
    display_name: str
    description: str
    config_model: type[BaseModel]
    credential_mode: CredentialMode
    #: Only usable in development or with ``SKYLINE_DEMO_PROVIDER_ENABLED=true``.
    demo_only: bool = False


PROVIDERS: Final[Mapping[str, ProviderInfo]] = {
    "fake": ProviderInfo(
        provider="fake",
        display_name="Fake cloud (demo)",
        description=(
            "A simulated company with a few misconfigurations, for trying Skyline without a "
            "cloud account. It makes no network calls."
        ),
        config_model=FakeConfig,
        credential_mode=CredentialMode.GENERATED,
        demo_only=True,
    ),
}


def provider_info(provider: str) -> ProviderInfo | None:
    """Metadata for ``provider``, or ``None`` if Skyline has no such connector."""
    return PROVIDERS.get(provider)
