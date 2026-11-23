"""The runner treats connector output as untrusted: validate, cap, redact, isolate."""

from __future__ import annotations

import math
from collections.abc import AsyncIterator, Sequence
from typing import ClassVar

import pytest

from skyline_connectors.base import (
    ApiCall,
    AssetRecord,
    RelationshipRecord,
    Scope,
    ValidationResult,
)
from skyline_connectors.runner import (
    RecordRejectedError,
    RunnerLimits,
    collect_all,
    safe_reason,
    sanitise_asset,
    sanitise_relationship,
)
from skyline_core.redaction import RedactionRules

SCOPE = Scope(kind="region", id="r1")
LIMITS = RunnerLimits()
FAKE_AWS_KEY_ID = "AKIA" + "B" * 16


def _asset(**overrides: object) -> AssetRecord:
    values: dict[str, object] = {
        "resource_type": "fake.compute.vm",
        "native_id": "fake://a/vm/1",
        "name": "vm",
        "account_id": "a",
        "region": "r1",
        "tags": {},
        "raw_config": {"id": "1"},
        "scope_id": "r1",
    }
    values.update(overrides)
    return AssetRecord(**values)  # type: ignore[arg-type]


def _sanitise(record: AssetRecord, limits: RunnerLimits = LIMITS) -> object:
    return sanitise_asset(
        record,
        scope=SCOPE,
        provider="fake",
        rules=RedactionRules(),
        hmac_key=b"k" * 32,
        limits=limits,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"resource_type": "aws.ec2.instance"},  # wrong provider prefix
        {"resource_type": "fake.vm"},  # not enough segments
        {"resource_type": "Fake.Compute.VM"},
        {"scope_id": "other"},
        {"native_id": ""},
        {"native_id": "x" * 3000},
        {"name": "n" * 600},
        {"raw_config": {"blob": "x" * (300 * 1024)}},
        {"raw_config": {"bad": math.nan}},
        {"raw_config": {"bad": object()}},
    ],
)
def test_invalid_assets_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(RecordRejectedError):
        _sanitise(_asset(**overrides))


def test_tags_are_capped_and_secret_values_masked() -> None:
    tags = {f"k{i}": "v" for i in range(150)} | {
        "k0": f"rotate {FAKE_AWS_KEY_ID}",
        "long": "x" * 900,
    }
    asset = _sanitise(_asset(tags=tags))
    assert len(asset.tags) == 100  # type: ignore[attr-defined]
    assert asset.tags["k0"] == "[REDACTED]"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "record",
    [
        RelationshipRecord("a", "b", "Bad Type"),
        RelationshipRecord("", "b", "attached_to"),
        RelationshipRecord("a", "b" * 3000, "attached_to"),
        RelationshipRecord("a", "b", "attached_to", {"blob": "x" * 5000}),
    ],
)
def test_invalid_relationships_are_rejected(record: RelationshipRecord) -> None:
    with pytest.raises(RecordRejectedError):
        sanitise_relationship(record, LIMITS)


class _Flaky:
    provider: ClassVar[str] = "fake"
    api_allowlist: ClassVar[frozenset[ApiCall]] = frozenset()

    def __init__(
        self, records: dict[str, list[AssetRecord | RelationshipRecord] | Exception]
    ) -> None:
        self.records = records

    async def validate_credentials(self) -> ValidationResult:
        return ValidationResult(ok=True)

    async def discover_scopes(self) -> Sequence[Scope]:
        return [Scope(kind="region", id=k) for k in self.records]

    async def collect(self, scope: Scope) -> AsyncIterator[AssetRecord | RelationshipRecord]:
        outcome = self.records[scope.id]
        if isinstance(outcome, Exception):
            raise outcome
        for record in outcome:
            yield record


async def test_unexpected_errors_are_isolated_and_hidden() -> None:
    secret_text = "password=" + "p" * 12
    connector = _Flaky(
        {
            "r1": [
                _asset(),
                _asset(resource_type="bad"),
                RelationshipRecord("a", "b", "attached_to"),
            ],
            "r2": RuntimeError(secret_text),
        }
    )
    results = await collect_all(
        connector,
        await connector.discover_scopes(),
        provider="fake",
        rules=RedactionRules(),
        hmac_key=b"k" * 32,
    )
    ok, failed = results
    assert ok.ok and len(ok.assets) == 1 and ok.rejected == 1 and len(ok.relationships) == 1
    assert failed.error == "unexpected error while collecting (see worker logs)"
    assert secret_text not in str(failed.error)


async def test_record_cap_fails_the_scope() -> None:
    connector = _Flaky({"r1": [_asset(native_id=f"fake://a/vm/{i}") for i in range(5)]})
    results = await collect_all(
        connector,
        await connector.discover_scopes(),
        provider="fake",
        rules=RedactionRules(),
        hmac_key=b"k" * 32,
        limits=RunnerLimits(max_records_per_scope=3),
    )
    assert results[0].error == "scope returned more records than allowed"


def test_safe_reason_for_timeouts() -> None:
    assert safe_reason(TimeoutError()) == "collection timed out"
