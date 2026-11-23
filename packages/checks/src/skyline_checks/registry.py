"""Evaluator registry. Evaluators register themselves by check ID with a decorator.

YAML definitions never name an import path (ADR-0009), so loading a check file can't cause
arbitrary code to be imported.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType

from skyline_checks.engine import Evaluator

_EVALUATORS: dict[str, Evaluator] = {}


def evaluator(check_id: str) -> Callable[[Evaluator], Evaluator]:
    """Register ``fn`` as the evaluator for ``check_id``."""

    def register(fn: Evaluator) -> Evaluator:
        if check_id in _EVALUATORS:
            msg = f"duplicate evaluator for {check_id}"
            raise ValueError(msg)
        _EVALUATORS[check_id] = fn
        return fn

    return register


def registered_evaluators() -> Mapping[str, Evaluator]:
    """All registered evaluators (read-only view). Importing evaluators fills it."""
    import skyline_checks.evaluators  # noqa: F401, PLC0415 - static list of evaluator modules

    return MappingProxyType(_EVALUATORS)
