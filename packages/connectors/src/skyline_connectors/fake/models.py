"""Config and credential models for the fake connector (safe for the API to import)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

#: Fixes the demo can apply to its fake resources, one per seeded finding.
FakeFix = Literal[
    "remove_public_ip",
    "close_admin_ports",
    "encrypt_bucket",
    "enable_mfa",
    "upgrade_os",
]

FAKE_FIXES: tuple[FakeFix, ...] = (
    "remove_public_ip",
    "close_admin_ports",
    "encrypt_bucket",
    "enable_mfa",
    "upgrade_os",
)


class FakeConfig(BaseModel):
    """Non-secret settings for a fake integration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    simulate_fixes: list[FakeFix] = Field(default_factory=list, max_length=len(FAKE_FIXES))
    #: Scope IDs that fail on purpose, to demonstrate partial-failure handling.
    fail_scopes: list[Literal["fake-north-1", "fake-south-1", "fake-acct-001"]] = Field(
        default_factory=list, max_length=3
    )


class FakeCredentials(BaseModel):
    """A generated placeholder credential. It exercises the encrypt/decrypt path end to end."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    api_key: SecretStr = Field(min_length=32, max_length=256)
