"""The runner treats connector output as untrusted: validate, cap, redact, isolate."""

from __future__ import annotations

import contextlib
import math
from collections.abc import AsyncIterator, Sequence
from typing import ClassVar

import pytest

from skyline_connectors.base import (
    ApiCall,
    ApiNotAllowedError,
    AssetRecord,
    RelationshipRecord,
    Scope,
    ValidationResult,
)
from skyline_connectors.runner import (
    RecordRejectedError,
    RunnerLimits,
    ScopeDiscoveryError,
    ScopeResult,
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


async def _run(
    records: dict[str, list[AssetRecord | RelationshipRecord] | Exception],
    limits: RunnerLimits | None = None,
) -> list[ScopeResult]:
    connector = _Flaky(records)
    return await collect_all(
        connector,
        await connector.discover_scopes(),
        provider="fake",
        rules=RedactionRules(),
        hmac_key=b"k" * 32,
        limits=limits,
    )


async def test_unexpected_errors_are_isolated_and_hidden() -> None:
    secret_text = "password=" + "p" * 12
    results = await _run(
        {
            "r1": [
                _asset(),
                _asset(native_id="fake://a/vm/2", resource_type="bad"),
                RelationshipRecord("fake://a/vm/1", "b", "attached_to"),
            ],
            "r2": RuntimeError(secret_text),
        }
    )
    ok, failed = results
    assert ok.ok and len(ok.assets) == 1 and ok.rejected == 1 and len(ok.relationships) == 1
    assert ok.rejected_ids == {"fake://a/vm/2"} and not ok.unsafe_to_delete
    assert failed.error == "unexpected error while collecting (see worker logs)"
    assert secret_text not in str(failed.error)


async def test_unexpected_error_messages_are_not_logged(
    capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    secret_text = "password=" + "q" * 12
    await _run({"r1": RuntimeError(secret_text)})
    out = capsys.readouterr()
    # Depending on logging setup, structlog writes to stdout or through stdlib logging.
    logged = out.out + out.err + caplog.text
    assert secret_text not in logged
    assert "RuntimeError" in logged


async def test_rejected_record_without_usable_id_makes_scope_unsafe_to_delete() -> None:
    (result,) = await _run({"r1": [_asset(), _asset(native_id="")]})
    assert result.ok and result.unsafe_to_delete and result.rejected == 1


@pytest.mark.parametrize(
    "raw",
    [
        {"bad": "nul\x00byte"},
        {"bad": "lone \ud800 surrogate"},
        {1: "non-text key"},
        {"nested": {"k\x00": "v"}},
        {"set": {1, 2}},
    ],
)
async def test_unstorable_json_is_rejected_and_kept_as_not_deleted(
    raw: dict[object, object],
) -> None:
    (result,) = await _run({"r1": [_asset(raw_config=raw)]})
    assert result.ok and not result.assets
    assert result.rejected_ids == {"fake://a/vm/1"}


async def test_duplicates_within_a_scope_keep_the_first() -> None:
    first = _asset(name="first")
    (result,) = await _run({"r1": [first, _asset(name="second")]})
    assert [a.name for a in result.assets] == ["first"] and result.duplicates == 1


async def test_duplicates_across_scopes_are_stored_once() -> None:
    results = await _run({"r1": [_asset()], "r2": [_asset(scope_id="r2", region="r2")]})
    assert len(results[0].assets) == 1 and not results[1].assets
    assert results[1].duplicates == 1


async def test_failed_scope_does_not_claim_shared_ids() -> None:
    results = await _run({"r1": RuntimeError("boom"), "r2": [_asset(scope_id="r2")]})
    assert len(results[1].assets) == 1


async def test_edges_from_another_scopes_assets_are_dropped() -> None:
    (result,) = await _run(
        {
            "r1": [
                _asset(),
                RelationshipRecord("fake://a/vm/1", "x", "attached_to"),
                RelationshipRecord("fake://other/vm/9", "x", "attached_to"),
            ]
        }
    )
    assert [r.src_native_id for r in result.relationships] == ["fake://a/vm/1"]
    assert result.rejected == 1


async def test_relationship_properties_are_redacted() -> None:
    (result,) = await _run(
        {
            "r1": [
                _asset(),
                RelationshipRecord(
                    "fake://a/vm/1", "x", "attached_to", {"note": f"key {FAKE_AWS_KEY_ID}"}
                ),
            ]
        }
    )
    assert FAKE_AWS_KEY_ID not in str(result.relationships[0].properties)


async def test_scope_byte_cap_fails_the_scope() -> None:
    records: list[AssetRecord | RelationshipRecord] = [
        _asset(native_id=f"fake://a/vm/{i}", raw_config={"blob": "x" * 1000}) for i in range(5)
    ]
    (result,) = await _run({"r1": records}, RunnerLimits(max_bytes_per_scope=3000))
    assert result.error == "scope returned more data than allowed"
    assert not result.assets


async def test_scan_byte_budget_is_shared_across_scopes() -> None:
    def big(scope: str) -> list[AssetRecord | RelationshipRecord]:
        return [
            _asset(native_id=f"fake://{scope}/vm/{i}", scope_id=scope, raw_config={"b": "x" * 1000})
            for i in range(2)
        ]

    results = await _run(
        {"r1": big("r1"), "r2": big("r2")},
        RunnerLimits(max_bytes_per_scan=3000, max_concurrent_scopes=1),
    )
    assert results[0].ok and not results[1].ok


@pytest.mark.parametrize(
    "scope_ids",
    [[], ["r1", "r1"], ["bad id with spaces"], [f"r{i}" for i in range(4)]],
)
async def test_unusable_scope_lists_fail_discovery(scope_ids: list[str]) -> None:
    connector = _Flaky({key: [] for key in scope_ids})
    scopes = [Scope(kind="region", id=s) for s in scope_ids]
    with pytest.raises(ScopeDiscoveryError):
        await collect_all(
            connector,
            scopes,
            provider="fake",
            rules=RedactionRules(),
            hmac_key=b"k" * 32,
            limits=RunnerLimits(max_scopes=3),
        )


async def test_off_allowlist_call_is_flagged_as_read_only_violation() -> None:
    (result,) = await _run({"r1": ApiNotAllowedError(ApiCall("ec2", "TerminateInstances"))})
    assert result.read_only_violation and not result.ok and not result.assets


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


async def test_tags_and_edges_count_against_the_byte_budgets() -> None:
    tags = {f"k{i}": "v" * 500 for i in range(50)}  # ~25 KB per asset, tiny raw config
    records: list[AssetRecord | RelationshipRecord] = [
        _asset(native_id=f"fake://a/vm/{i}", tags=tags) for i in range(5)
    ]
    (result,) = await _run({"r1": records}, RunnerLimits(max_bytes_per_scope=60_000))
    assert result.error == "scope returned more data than allowed"
    edges: list[AssetRecord | RelationshipRecord] = [_asset()] + [
        RelationshipRecord("fake://a/vm/1", f"x{i}", "attached_to", {"p": "y" * 3000})
        for i in range(30)
    ]
    (result,) = await _run({"r1": edges}, RunnerLimits(max_bytes_per_scope=60_000))
    assert not result.ok


async def test_duplicates_and_rejects_count_towards_the_record_caps() -> None:
    (result,) = await _run({"r1": [_asset()] * 5}, RunnerLimits(max_records_per_scope=3))
    assert result.error == "scope returned more records than allowed"
    results = await _run(
        {
            "r1": [_asset(native_id=f"fake://a/vm/{i}") for i in range(3)],
            "r2": [_asset(native_id="")] * 3,
        },
        RunnerLimits(max_records_per_scan=4, max_concurrent_scopes=1),
    )
    assert results[0].ok and results[1].error == "scope returned more data than allowed"


def test_provider_text_is_cleaned_before_storage() -> None:
    from skyline_connectors.base import ConnectorError
    from skyline_connectors.runner import clean_text

    assert clean_text("bad\x00 text\x1b[31m \ud800ok") == "bad text[31m ok"
    assert len(clean_text("x" * 1000)) == 300
    assert "\x00" not in safe_reason(ConnectorError("provider said \x00 no"))


async def test_violations_are_seen_even_when_a_connector_swallows_them() -> None:
    from skyline_connectors.base import ConnectorError, ReadOnlyGuardError
    from skyline_connectors.gateway import GuardedGateway

    assert not issubclass(ApiNotAllowedError, ConnectorError)
    assert issubclass(ApiNotAllowedError, ReadOnlyGuardError)

    class _Echo:
        async def send(self, api: ApiCall, params: object) -> dict[str, object]:
            return {}

    gateway = GuardedGateway(_Echo(), frozenset({ApiCall("fake", "ListRegions")}))  # type: ignore[arg-type]
    with contextlib.suppress(Exception):  # a careless connector swallowing everything
        await gateway.call(ApiCall("fake", "DeleteBucket"))
    assert gateway.violations == (ApiCall("fake", "DeleteBucket"),)
