"""Every check has a passing and a failing fixture that behave as labelled (CLAUDE.md)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from skyline_checks.engine import AssetView, GraphContext, Result, Status, evaluate, run_check
from skyline_checks.loader import (
    CatalogueError,
    LoadedCheck,
    content_hash,
    load_checks,
    parse_definition,
)
from skyline_checks.registry import evaluator

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 23, tzinfo=UTC)
CHECKS = {c.definition.id: c for c in load_checks()}


def _view(index: int, data: dict[str, Any]) -> AssetView:
    return AssetView(
        id=f"a{index}",
        native_id=f"fake://test/{index}",
        resource_type=data["resource_type"],
        provider="fake",
        name=data.get("name"),
        region=None,
        account_id=None,
        tags=data.get("tags", {}),
        config=data["config"],
    )


def _run_fixture(check: LoadedCheck, path: Path) -> Result:
    fixture = json.loads(path.read_text(encoding="utf-8"))
    asset = _view(0, fixture["asset"])
    related = [_view(i + 1, r["asset"]) for i, r in enumerate(fixture.get("related", []))]
    edges = [
        (asset.id, other.id, r["type"])
        if r["direction"] == "out"
        else (other.id, asset.id, r["type"])
        for r, other in zip(fixture.get("related", []), related, strict=True)
    ]
    now = datetime.fromisoformat(fixture["now"]) if "now" in fixture else NOW
    ctx = GraphContext([asset, *related], edges, now=now)
    return run_check(check, asset, ctx)


def test_the_phase_0_catalogue() -> None:
    assert set(CHECKS) == {
        "fake.compute.vm_public_exposure",
        "fake.network.sg_admin_ports_open",
        "fake.storage.bucket_encryption",
        "fake.identity.admin_without_mfa",
        "fake.compute.unsupported_os",
    }


@pytest.mark.parametrize("check_id", sorted(CHECKS))
@pytest.mark.parametrize("label", ["pass", "fail"])
def test_fixture_behaves_as_labelled(check_id: str, label: str) -> None:
    path = FIXTURES / check_id / f"{label}.json"
    assert path.exists(), f"missing {label}.json fixture for {check_id}"
    result = _run_fixture(CHECKS[check_id], path)
    assert result.status == Status(label), result.evidence


def test_no_fixture_directories_for_unknown_checks() -> None:
    assert {p.name for p in FIXTURES.iterdir() if p.is_dir()} == set(CHECKS)


def test_content_hashes_are_stable_and_distinct() -> None:
    hashes = {c.content_hash for c in CHECKS.values()}
    assert len(hashes) == len(CHECKS)
    for check in CHECKS.values():
        assert content_hash(check.definition) == check.content_hash


def test_admin_without_mfa_is_not_applicable_for_non_admins() -> None:
    check = CHECKS["fake.identity.admin_without_mfa"]
    user = _view(0, {"resource_type": "fake.identity.user", "config": {"mfa_enabled": False}})
    assert run_check(check, user, GraphContext([user], [], now=NOW)).status is Status.NOT_APPLICABLE


@pytest.mark.parametrize("os_info", [None, {"end_of_support": "soon"}, {"name": "x"}])
def test_unsupported_os_errors_on_missing_data(os_info: object) -> None:
    check = CHECKS["fake.compute.unsupported_os"]
    vm = _view(0, {"resource_type": "fake.compute.vm", "config": {"os": os_info}})
    assert run_check(check, vm, GraphContext([vm], [], now=NOW)).status is Status.ERROR


def test_vm_without_public_ip_passes_and_garbage_rules_are_ignored() -> None:
    check = CHECKS["fake.compute.vm_public_exposure"]
    vm = _view(0, {"resource_type": "fake.compute.vm", "config": {"public_ip": None}})
    assert run_check(check, vm, GraphContext([vm], [], now=NOW)).status is Status.PASS
    sg_check = CHECKS["fake.network.sg_admin_ports_open"]
    weird = _view(
        1,
        {
            "resource_type": "fake.network.security_group",
            "config": {
                "ingress": [
                    "junk",
                    {"protocol": "udp", "from_port": 22, "to_port": 22, "sources": ["0.0.0.0/0"]},
                    {"protocol": "tcp", "from_port": "22", "to_port": 22, "sources": ["0.0.0.0/0"]},
                ]
            },
        },
    )
    assert run_check(sg_check, weird, GraphContext([weird], [], now=NOW)).status is Status.PASS


def test_engine_isolates_crashing_and_misbehaving_evaluators() -> None:
    base = CHECKS["fake.storage.bucket_encryption"]
    bucket = _view(0, {"resource_type": "fake.storage.bucket", "config": {}})
    ctx = GraphContext([bucket], [], now=NOW)

    def boom(_a: AssetView, _c: object) -> Result:
        raise RuntimeError("secret=" + "x" * 10)

    def huge(_a: AssetView, _c: object) -> Result:
        return Result.failed(blob="x" * 10_000)

    def not_json(_a: AssetView, _c: object) -> Result:
        return Result.failed(value=object())  # type: ignore[arg-type]

    def wrong_type(_a: AssetView, _c: object) -> Result:
        return "fail"  # type: ignore[return-value]

    for fn, reason in [
        (boom, "the check could not be evaluated"),
        (huge, "evaluator returned too much evidence"),
        (not_json, "evaluator returned evidence that is not JSON"),
        (wrong_type, "evaluator returned an invalid result"),
    ]:
        check = LoadedCheck(base.definition, base.content_hash, fn)  # type: ignore[arg-type]
        result = run_check(check, bucket, ctx)
        assert result.status is Status.ERROR
        assert result.evidence == {"reason": reason}


def test_evaluate_selects_checks_by_provider_and_resource_type() -> None:
    bucket = _view(0, {"resource_type": "fake.storage.bucket", "config": {}})
    user = _view(1, {"resource_type": "fake.identity.user", "config": {}})
    ctx = GraphContext([bucket, user], [], now=NOW)
    results = evaluate(list(CHECKS.values()), ctx, provider="fake")
    assert {(e.check_id, e.asset.id) for e in results} == {
        ("fake.storage.bucket_encryption", "a0"),
        ("fake.identity.admin_without_mfa", "a1"),
    }
    assert evaluate(list(CHECKS.values()), ctx, provider="aws") == []


VALID = """
id: fake.storage.example
version: 1
title: An example check title
severity: low
provider: fake
resource_types: [fake.storage.bucket]
description: A description long enough.
rationale: A rationale long enough.
remediation:
  summary: Do the right thing please.
  steps: [Step one]
"""


def test_parse_valid_definition() -> None:
    assert parse_definition(VALID, source="x.yaml").id == "fake.storage.example"


@pytest.mark.parametrize(
    "text",
    [
        VALID + "unknown_field: 1\n",
        VALID.replace("severity: low", "severity: catastrophic"),
        VALID.replace("id: fake.storage.example", "id: aws.storage.example"),
        VALID.replace("[fake.storage.bucket]", "[aws.s3.bucket]"),
        VALID + "references:\n  - title: Insecure\n    url: http://example.com\n",
        VALID + "tags: [Not Valid]\n",
        VALID.replace("[fake.storage.bucket]", "[Bad]"),
        "!!python/object/apply:os.system ['echo pwned']",
        "x: [unclosed",
        "a" * (65 * 1024),
    ],
)
def test_invalid_definitions_are_rejected(text: str) -> None:
    with pytest.raises(CatalogueError):
        parse_definition(text, source="bad.yaml")


def test_duplicate_evaluator_registration_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        evaluator("fake.storage.bucket_encryption")(lambda a, c: Result.passed())
