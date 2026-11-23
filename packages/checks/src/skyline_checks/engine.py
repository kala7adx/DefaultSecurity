"""Check engine: runs pure evaluators over stored assets (collect once, evaluate many).

Evaluators get an :class:`AssetView` and a read-only :class:`EvalContext` for graph lookups.
They do no I/O. A crashing evaluator yields ``error`` for that asset only, and ``error`` /
``not_applicable`` never resolve a finding.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Literal, Protocol

from skyline_core.logging import get_logger
from skyline_core.types import JSON

if TYPE_CHECKING:
    from skyline_checks.loader import LoadedCheck

_log = get_logger(__name__)
_MAX_EVIDENCE_BYTES: Final = 4096

Direction = Literal["out", "in"]


class Status(StrEnum):
    PASS = "pass"  # noqa: S105 - a check status, not a password
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class Result:
    status: Status
    evidence: Mapping[str, JSON] = field(default_factory=dict)

    @classmethod
    def passed(cls, **evidence: JSON) -> Result:
        return cls(Status.PASS, evidence)

    @classmethod
    def failed(cls, **evidence: JSON) -> Result:
        return cls(Status.FAIL, evidence)

    @classmethod
    def not_applicable(cls, reason: str) -> Result:
        return cls(Status.NOT_APPLICABLE, {"reason": reason})

    @classmethod
    def error(cls, reason: str) -> Result:
        return cls(Status.ERROR, {"reason": reason})


@dataclass(frozen=True, slots=True)
class AssetView:
    """A read-only view of a stored asset (config is already redacted)."""

    id: str
    native_id: str
    resource_type: str
    provider: str
    name: str | None
    region: str | None
    account_id: str | None
    tags: Mapping[str, str]
    config: Mapping[str, JSON]


class EvalContext(Protocol):
    """What an evaluator may look at besides the asset itself."""

    @property
    def now(self) -> datetime: ...

    def related(
        self, asset: AssetView, rel_type: str, direction: Direction
    ) -> Sequence[AssetView]: ...


type Evaluator = Callable[[AssetView, EvalContext], Result]


class GraphContext:
    """An in-memory graph over one integration's assets and relationships."""

    def __init__(
        self,
        assets: Iterable[AssetView],
        relationships: Iterable[tuple[str, str, str]],
        *,
        now: datetime,
    ) -> None:
        self._assets = {a.id: a for a in assets}
        self._out: dict[tuple[str, str], list[str]] = defaultdict(list)
        self._in: dict[tuple[str, str], list[str]] = defaultdict(list)
        for src, dst, rel_type in relationships:
            self._out[(src, rel_type)].append(dst)
            self._in[(dst, rel_type)].append(src)
        self._now = now

    @property
    def now(self) -> datetime:
        return self._now

    @property
    def assets(self) -> Sequence[AssetView]:
        return list(self._assets.values())

    def related(self, asset: AssetView, rel_type: str, direction: Direction) -> Sequence[AssetView]:
        index = self._out if direction == "out" else self._in
        return [self._assets[i] for i in index.get((asset.id, rel_type), []) if i in self._assets]


@dataclass(frozen=True, slots=True)
class Evaluation:
    check_id: str
    asset: AssetView
    result: Result


def _bounded_evidence(result: Result) -> Result:
    try:
        size = len(json.dumps(result.evidence, allow_nan=False))
    except (TypeError, ValueError):
        return Result.error("evaluator returned evidence that is not JSON")
    if size > _MAX_EVIDENCE_BYTES:
        return Result.error("evaluator returned too much evidence")
    return result


def run_check(check: LoadedCheck, asset: AssetView, ctx: EvalContext) -> Result:
    """Run one evaluator on one asset with error isolation."""
    try:
        result: object = check.evaluator(asset, ctx)
    except Exception as exc:
        _log.warning(
            "evaluator_failed", check_id=check.definition.id, error_type=type(exc).__name__
        )
        return Result.error("the check could not be evaluated")
    if not isinstance(result, Result):
        return Result.error("evaluator returned an invalid result")
    return _bounded_evidence(result)


def evaluate(
    checks: Sequence[LoadedCheck], ctx: GraphContext, *, provider: str
) -> list[Evaluation]:
    """Evaluate every enabled check for ``provider`` against every matching asset."""
    by_type: dict[str, list[LoadedCheck]] = defaultdict(list)
    for check in checks:
        if check.definition.provider == provider:
            for resource_type in check.definition.resource_types:
                by_type[resource_type].append(check)
    evaluations: list[Evaluation] = []
    for asset in ctx.assets:
        for check in by_type.get(asset.resource_type, []):
            evaluations.append(Evaluation(check.definition.id, asset, run_check(check, asset, ctx)))
    return evaluations
