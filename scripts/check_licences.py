"""Licence gate (ADR-0010): every dependency's licence must be on the allowlist.

    uv run pip-licenses --format=json --from=mixed | uv run python scripts/check_licences.py python
    pnpm --dir apps/web licenses list --prod --json | uv run python scripts/check_licences.py node

An allowlist, not a deny list: anything unknown, proprietary (UNLICENSED, "SEE LICENSE IN"),
copyleft or source-available fails, and so does empty input. SPDX expressions are parsed
properly (brackets; AND binds tighter than OR; WITH exceptions rejected). Python classifier
names are mapped to SPDX first.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Final

ALLOWED: Final = frozenset(
    {
        "MIT",
        "MIT-0",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "PSF-2.0",
        "Python-2.0",
        "Unlicense",
        "CC0-1.0",
        "BlueOak-1.0.0",
        # Weak, file-level copyleft; used unmodified (certifi, pathspec). Flagged to the owner.
        "MPL-2.0",
    }
)
#: Licences allowed only for named packages (data, not code).
PER_PACKAGE: Final = {"CC-BY-4.0": {"caniuse-lite"}}
#: Python trove classifiers and common free-text names -> SPDX.
ALIASES: Final = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "BSD": "BSD-3-Clause",
    "ISC License (ISCL)": "ISC",
    "Python Software Foundation License": "PSF-2.0",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
}


WORKSPACE: Final = frozenset(
    {
        "skyline-workspace",
        "skyline-core",
        "skyline-connectors",
        "skyline-checks",
        "skyline-frameworks",
        "skyline-api",
        "skyline-worker",
    }
)
_TOKEN: Final = re.compile(r"\(|\)|[^\s()]+")


class _ExpressionError(ValueError):
    """Not a valid SPDX expression: rejected (fail closed)."""


def _allowed_term(term: str, package: str) -> bool:
    term = ALIASES.get(term, term)
    return term in ALLOWED or package in PER_PACKAGE.get(term, set())


def _parse_or(tokens: list[str], pos: int, package: str) -> tuple[bool, int]:
    value, pos = _parse_and(tokens, pos, package)
    while pos < len(tokens) and tokens[pos].upper() == "OR":
        right, pos = _parse_and(tokens, pos + 1, package)
        value = value or right
    return value, pos


def _parse_and(tokens: list[str], pos: int, package: str) -> tuple[bool, int]:
    value, pos = _parse_atom(tokens, pos, package)
    while pos < len(tokens) and tokens[pos].upper() == "AND":
        right, pos = _parse_atom(tokens, pos + 1, package)
        value = value and right
    return value, pos


def _parse_atom(tokens: list[str], pos: int, package: str) -> tuple[bool, int]:
    if pos >= len(tokens):
        raise _ExpressionError("expression ends early")
    word = tokens[pos]
    if word == "(":
        value, pos = _parse_or(tokens, pos + 1, package)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise _ExpressionError("unbalanced brackets")
        return value, pos + 1
    if word == ")" or word.upper() in {"AND", "OR", "WITH"}:
        raise _ExpressionError(f"unexpected {word!r}")
    return _allowed_term(word, package), pos + 1


def _allowed_expression(expression: str, package: str) -> bool:
    expression = expression.strip()
    if expression in ALIASES:  # a free-text classifier name, e.g. "MIT License"
        return _allowed_term(expression, package)
    tokens = _TOKEN.findall(expression)
    try:
        value, pos = _parse_or(tokens, 0, package)
    except _ExpressionError:
        return False
    return value and pos == len(tokens)  # trailing words: free text we don't know


def allowed(expression: str, package: str) -> bool:
    """Evaluate an SPDX expression (brackets, AND binds tighter than OR, WITH rejected).
    pip-licenses joins several classifiers with "; ", which means all of them apply."""
    expression = expression.strip()
    if not expression or expression.upper() in {"UNKNOWN", "UNLICENSED"}:
        return False
    return all(_allowed_expression(part, package) for part in expression.split(";"))


def python_rows(data: list[dict[str, str]]) -> list[tuple[str, str]]:
    return [(row["Name"], row["License"]) for row in data if row["Name"] not in WORKSPACE]


def node_rows(data: dict[str, list[dict[str, str]]]) -> list[tuple[str, str]]:
    return [(pkg["name"], licence) for licence, pkgs in data.items() for pkg in pkgs]


def main(argv: list[str]) -> int:
    kind = argv[1] if len(argv) > 1 else ""
    raw = sys.stdin.read()
    if kind == "python":
        rows = python_rows(json.loads(raw))
    elif kind == "node":
        rows = node_rows(json.loads(raw[raw.index("{") :]))
    else:
        print("usage: check_licences.py python|node < licences.json", file=sys.stderr)
        return 2
    if not rows:  # an empty listing means the producer failed, not that all is well
        print(f"{kind}: no packages read; refusing to pass", file=sys.stderr)
        return 1
    bad = sorted({(name, licence) for name, licence in rows if not allowed(licence, name)})
    for name, licence in bad:
        print(f"not allowed: {name}: {licence}", file=sys.stderr)
    print(f"{kind}: {len(rows)} packages checked, {len(bad)} not allowed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
