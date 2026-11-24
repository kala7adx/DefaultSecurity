"""Load and validate the check catalogue shipped with this package."""

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass
from functools import cache
from importlib import resources
from importlib.resources.abc import Traversable
from typing import Final

import yaml
from pydantic import ValidationError

from skyline_checks.engine import Evaluator
from skyline_checks.registry import registered_evaluators
from skyline_checks.schema import CheckDefinition
from skyline_core.redaction import canonical_json

_MAX_FILE_BYTES: Final = 64 * 1024


class CatalogueError(ValueError):
    """The check catalogue is invalid. The message names the offending file or check."""


@dataclass(frozen=True, slots=True)
class LoadedCheck:
    definition: CheckDefinition
    content_hash: bytes
    evaluator: Evaluator


def _yaml_files(root: Traversable) -> list[Traversable]:
    files: list[Traversable] = []
    for entry in root.iterdir():
        if entry.is_dir():
            files.extend(_yaml_files(entry))
        elif entry.name.endswith(".yaml"):
            files.append(entry)
    return sorted(files, key=lambda f: f.name)


def parse_definition(text: str, *, source: str) -> CheckDefinition:
    """Parse one YAML document with ``safe_load`` and validate it strictly."""
    if len(text.encode()) > _MAX_FILE_BYTES:
        msg = f"{source}: file is too large"
        raise CatalogueError(msg)
    try:
        data = yaml.safe_load(text)
        return CheckDefinition.model_validate(data)
    except (yaml.YAMLError, ValidationError, ValueError) as exc:
        msg = f"{source}: {exc}"
        raise CatalogueError(msg) from exc


def content_hash(definition: CheckDefinition, evaluator: Evaluator | None = None) -> bytes:
    """SHA-256 of the canonical definition and the evaluator's source code, used to detect
    edits without a version bump. Helpers the evaluator calls are not included, so a change
    to a shared helper still needs a deliberate version bump."""
    digest = hashlib.sha256(canonical_json(definition.model_dump(mode="json")))
    if evaluator is not None:
        digest.update(b"\x00evaluator\x00")
        digest.update(inspect.getsource(evaluator).encode())
    return digest.digest()


@cache
def load_checks() -> tuple[LoadedCheck, ...]:
    """Every check definition paired with its evaluator. Fails on any inconsistency."""
    evaluators = registered_evaluators()
    root = resources.files("skyline_checks").joinpath("definitions")
    checks: dict[str, LoadedCheck] = {}
    for file in _yaml_files(root):
        definition = parse_definition(file.read_text(encoding="utf-8"), source=file.name)
        if definition.id in checks:
            msg = f"{file.name}: duplicate check id {definition.id}"
            raise CatalogueError(msg)
        fn = evaluators.get(definition.id)
        if fn is None:
            msg = f"{file.name}: no evaluator registered for {definition.id}"
            raise CatalogueError(msg)
        checks[definition.id] = LoadedCheck(definition, content_hash(definition, fn), fn)
    orphans = sorted(set(evaluators) - set(checks))
    if orphans:
        msg = f"evaluators without a definition: {', '.join(orphans)}"
        raise CatalogueError(msg)
    return tuple(checks[k] for k in sorted(checks))
