"""The licence gate is an allowlist and fails closed (ADR-0010)."""

from __future__ import annotations

import io
import json

import check_licences as gate
import pytest


@pytest.mark.parametrize(
    ("expression", "package"),
    [
        ("MIT", "x"),
        ("MIT OR Apache-2.0", "x"),
        ("Apache-2.0 AND MIT", "x"),
        ("(MIT OR GPL-3.0-only) AND BSD-3-Clause", "x"),
        ("MIT License", "x"),
        ("Mozilla Public License 2.0 (MPL 2.0)", "certifi"),
        ("MIT; Apache Software License", "x"),
        ("CC-BY-4.0", "caniuse-lite"),
    ],
)
def test_allowed(expression: str, package: str) -> None:
    assert gate.allowed(expression, package)


@pytest.mark.parametrize(
    ("expression", "package"),
    [
        ("GPL-3.0 AND (MIT OR Apache-2.0)", "x"),
        ("AGPL-3.0-only AND (MIT OR ISC)", "x"),
        ("GNU Affero General Public License v3", "x"),
        ("UNLICENSED", "x"),
        ("UNKNOWN", "x"),
        ("SEE LICENSE IN LICENSE.md", "x"),
        ("Elastic-2.0", "x"),
        ("CC-BY-4.0", "some-code-package"),
        ("Apache-2.0 WITH LLVM-exception", "x"),
        ("(MIT OR Apache-2.0", "x"),
        ("MIT AND", "x"),
        ("Other/Proprietary License", "x"),
        ("MIT; GPL-2.0-only", "x"),
        ("", "x"),
    ],
)
def test_rejected(expression: str, package: str) -> None:
    assert not gate.allowed(expression, package)


def test_empty_input_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("[]"))
    assert gate.main(["x", "python"]) == 1


def test_workspace_packages_are_skipped_by_exact_name_only() -> None:
    rows = gate.python_rows(
        [
            {"Name": "skyline-core", "License": "Apache-2.0"},
            {"Name": "skyline-evil", "License": "GPL-3.0-only"},
        ]
    )
    assert rows == [("skyline-evil", "GPL-3.0-only")]


def test_node_listing_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = {"MIT": [{"name": "a"}], "AGPL-3.0": [{"name": "b"}]}
    monkeypatch.setattr("sys.stdin", io.StringIO("noise\n" + json.dumps(listing)))
    assert gate.main(["x", "node"]) == 1
