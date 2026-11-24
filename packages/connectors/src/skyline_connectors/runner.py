"""Runs a connector over its scopes and turns raw records into safe, bounded data.

Connector output is untrusted (it mirrors provider responses), so every record is validated
strictly (types, NUL bytes, lone surrogates, sizes), redacted, and de-duplicated here before
anything is stored. Each scope succeeds or fails on its own: a failed scope is reported with a
sanitised reason and its data is left untouched.

A record that is *rejected* is not the same as a resource that is *gone*: the native IDs of
rejected records are kept, and the worker never deletes those assets or resolves their
findings. If a rejected record has no usable native ID, its scope deletes nothing at all.
"""

from __future__ import annotations

import json
import math
import re
from asyncio import Semaphore, gather, timeout
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from skyline_connectors.base import (
    ApiNotAllowedError,
    AssetRecord,
    Connector,
    ConnectorError,
    ReadOnlyGuardError,
    RelationshipRecord,
    Scope,
)
from skyline_core.logging import get_logger
from skyline_core.redaction import (
    MAX_DEPTH,
    RedactionDepthError,
    RedactionRules,
    config_hash,
    contains_secret_pattern,
    redact_raw_config,
)
from skyline_core.types import JSON

_log = get_logger(__name__)

_RESOURCE_TYPE: Final = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*){2,4}$")
_REL_TYPE: Final = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_SCOPE_ID: Final = re.compile(r"^[A-Za-z0-9._:/@+=-]{1,256}$")
_MAX_LOGGED_REJECTIONS: Final = 10


@dataclass(frozen=True, slots=True)
class RunnerLimits:
    max_native_id: int = 2048
    max_name: int = 512
    max_tags: int = 100
    max_tag_key: int = 256
    max_tag_value: int = 512
    max_raw_config_bytes: int = 256 * 1024
    max_relationship_bytes: int = 4096
    max_records_per_scope: int = 50_000
    max_records_per_scan: int = 500_000
    max_bytes_per_scope: int = 64 * 1024 * 1024
    max_bytes_per_scan: int = 256 * 1024 * 1024
    max_scopes: int = 500
    scope_timeout_seconds: float = 15 * 60
    max_concurrent_scopes: int = 4


class RecordRejectedError(ValueError):
    """A record broke a validation rule or cap."""


class ScopeDiscoveryError(ConnectorError):
    """Discovery returned an unusable scope list (none, too many, duplicates, bad IDs)."""


@dataclass(frozen=True, slots=True)
class CollectedAsset:
    resource_type: str
    native_id: str
    name: str | None
    account_id: str | None
    region: str | None
    scope_id: str
    tags: dict[str, str]
    raw_config: dict[str, JSON]
    config_hash: bytes


@dataclass(frozen=True, slots=True)
class CollectedRelationship:
    src_native_id: str
    dst_native_id: str
    type: str
    properties: dict[str, JSON]


@dataclass(slots=True)
class ScopeResult:
    scope: Scope
    assets: list[CollectedAsset] = field(default_factory=list)
    relationships: list[CollectedRelationship] = field(default_factory=list)
    rejected: int = 0
    #: Native IDs of rejected records: never treat these as deleted.
    rejected_ids: set[str] = field(default_factory=set)
    #: A rejected record had no usable native ID, so this scope must not delete anything.
    unsafe_to_delete: bool = False
    duplicates: int = 0
    error: str | None = None
    #: The connector tried a call outside its allowlist (ADR-0005 layer 3): fail the scan.
    read_only_violation: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


# --------------------------------------------------------------------------- validation


def _check_text(value: object, limit: int, what: str, *, optional: bool = True) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        msg = f"{what} must be text"
        raise RecordRejectedError(msg)
    if len(value) > limit or (not value and not optional):
        msg = f"{what} has an invalid length"
        raise RecordRejectedError(msg)
    _check_string(value, what)
    return value


def _check_string(value: str, what: str) -> None:
    if "\x00" in value:
        msg = f"{what} contains a NUL character"
        raise RecordRejectedError(msg)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates can't be stored in PostgreSQL
        msg = f"{what} is not valid Unicode"
        raise RecordRejectedError(msg) from None


def _strict_scalar(value: object, what: str) -> JSON:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            msg = f"{what} contains a non-finite number"
            raise RecordRejectedError(msg)
        return value
    if isinstance(value, str):
        _check_string(value, what)
        return value
    msg = f"{what} contains a value that is not JSON"
    raise RecordRejectedError(msg)


def strict_json(value: object, what: str = "value", *, _depth: int = 0) -> JSON:
    """Return ``value`` if it is plain JSON storable in JSONB; raise RecordRejectedError."""
    if _depth > MAX_DEPTH:
        msg = f"{what} is nested too deeply"
        raise RecordRejectedError(msg)
    if isinstance(value, Mapping):
        out: dict[str, JSON] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                msg = f"{what} has a non-text key"
                raise RecordRejectedError(msg)
            _check_string(key, what)
            out[key] = strict_json(item, what, _depth=_depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [strict_json(item, what, _depth=_depth + 1) for item in value]
    return _strict_scalar(value, what)


def _json_size(value: JSON) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _clean_tags(tags: object, limits: RunnerLimits) -> dict[str, str]:
    if not isinstance(tags, Mapping):
        msg = "tags must be a mapping"
        raise RecordRejectedError(msg)
    cleaned: dict[str, str] = {}
    for key, value in list(tags.items())[: limits.max_tags]:
        key_text = _check_text(str(key)[: limits.max_tag_key], limits.max_tag_key, "tag key")
        value_text = _check_text(str(value)[: limits.max_tag_value], limits.max_tag_value, "tag")
        assert key_text is not None and value_text is not None  # noqa: S101 - not optional here
        # Tags are a common place for people to paste secrets.
        cleaned[key_text] = "[REDACTED]" if contains_secret_pattern(value_text) else value_text
    return cleaned


def usable_native_id(record: AssetRecord, limits: RunnerLimits) -> str | None:
    """The record's native ID if it is safe to use as a key, else None."""
    try:
        return _check_text(record.native_id, limits.max_native_id, "native ID", optional=False)
    except RecordRejectedError:
        return None


def sanitise_asset(
    record: AssetRecord,
    *,
    scope: Scope,
    provider: str,
    rules: RedactionRules,
    hmac_key: bytes,
    limits: RunnerLimits,
) -> CollectedAsset:
    """Validate, cap and redact one asset record. Raises RecordRejectedError."""
    native_id = usable_native_id(record, limits)
    if native_id is None:
        msg = "native ID is missing or invalid"
        raise RecordRejectedError(msg)
    resource_type = _check_text(record.resource_type, 128, "resource type", optional=False)
    if (
        resource_type is None
        or not _RESOURCE_TYPE.match(resource_type)
        or not resource_type.startswith(f"{provider}.")
    ):
        msg = "resource type is not valid for this provider"
        raise RecordRejectedError(msg)
    if record.scope_id != scope.id:
        msg = "record belongs to a different scope"
        raise RecordRejectedError(msg)
    raw = strict_json(dict(record.raw_config), "raw configuration")
    # Size is checked before redaction, which would otherwise do the work on huge inputs.
    if _json_size(raw) > limits.max_raw_config_bytes:
        msg = "raw configuration is too large"
        raise RecordRejectedError(msg)
    try:
        redacted = redact_raw_config(raw, rules=rules, hmac_key=hmac_key)
    except RedactionDepthError as exc:
        msg = "raw configuration is nested too deeply"
        raise RecordRejectedError(msg) from exc
    assert isinstance(redacted, dict)  # noqa: S101 - a dict stays a dict after redaction
    return CollectedAsset(
        resource_type=resource_type,
        native_id=native_id,
        name=_check_text(record.name, limits.max_name, "name"),
        account_id=_check_text(record.account_id, 256, "account ID"),
        region=_check_text(record.region, 64, "region"),
        scope_id=scope.id,
        tags=_clean_tags(record.tags, limits),
        raw_config=redacted,
        config_hash=config_hash(redacted),
    )


def sanitise_relationship(
    record: RelationshipRecord,
    limits: RunnerLimits,
    *,
    rules: RedactionRules | None = None,
    hmac_key: bytes = b"",
) -> CollectedRelationship:
    """Validate, cap and redact one relationship record. Raises RecordRejectedError."""
    rel_type = _check_text(record.type, 41, "relationship type", optional=False)
    if rel_type is None or not _REL_TYPE.match(rel_type):
        msg = "relationship type is not valid"
        raise RecordRejectedError(msg)
    src = _check_text(
        record.src_native_id, limits.max_native_id, "relationship source", optional=False
    )
    dst = _check_text(
        record.dst_native_id, limits.max_native_id, "relationship target", optional=False
    )
    assert src is not None and dst is not None  # noqa: S101 - not optional
    properties = strict_json(dict(record.properties), "relationship properties")
    if _json_size(properties) > limits.max_relationship_bytes:
        msg = "relationship properties are too large"
        raise RecordRejectedError(msg)
    redacted = redact_raw_config(properties, rules=rules or RedactionRules(), hmac_key=hmac_key)
    assert isinstance(redacted, dict)  # noqa: S101
    return CollectedRelationship(src, dst, rel_type, redacted)


_UNSTORABLE: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


def clean_text(value: str, limit: int = 300) -> str:
    """Text that came from a provider (error messages, credential-check details), made safe
    to store and show: no NUL, other controls or lone surrogates, and capped."""
    return _UNSTORABLE.sub("", value)[:limit]


def safe_reason(exc: BaseException) -> str:
    """A user-safe reason for a failure. Unexpected errors reveal nothing."""
    if isinstance(exc, ConnectorError | ReadOnlyGuardError):
        return clean_text(exc.safe_message)
    if isinstance(exc, TimeoutError):
        return "collection timed out"
    return "unexpected error while collecting (see worker logs)"


def validate_scopes(scopes: Sequence[Scope], limits: RunnerLimits) -> list[Scope]:
    """Discovery output must be non-empty, bounded, unique and well-formed."""
    if not scopes:
        msg = "the provider returned no scopes to collect"
        raise ScopeDiscoveryError(msg)
    if len(scopes) > limits.max_scopes:
        msg = "the provider returned more scopes than allowed"
        raise ScopeDiscoveryError(msg)
    seen: set[str] = set()
    for scope in scopes:
        if not isinstance(scope.id, str) or not _SCOPE_ID.match(scope.id):
            msg = "the provider returned an invalid scope ID"
            raise ScopeDiscoveryError(msg)
        if scope.id in seen:
            msg = "the provider returned duplicate scope IDs"
            raise ScopeDiscoveryError(msg)
        seen.add(scope.id)
    return list(scopes)


# --------------------------------------------------------------------------- collection


@dataclass(slots=True)
class _Budget:
    """Shared by every scope of one scan: bytes and records held in memory until stored."""

    remaining_bytes: int
    remaining_records: int

    def charge(self, size: int) -> bool:
        """Account for one record of ``size`` bytes. False once the scan is over budget."""
        self.remaining_bytes -= size
        self.remaining_records -= 1
        return self.remaining_bytes >= 0 and self.remaining_records >= 0


def _asset_size(asset: CollectedAsset) -> int:
    """Everything the asset holds, not just its raw config (tags, names and IDs count too)."""
    text = (asset.resource_type, asset.native_id, asset.name, asset.account_id, asset.region)
    return (
        _json_size(asset.raw_config)
        + sum(len(k) + len(v) for k, v in asset.tags.items())
        + sum(len(t) for t in text if t)
        + 64
    )


def _relationship_size(rel: CollectedRelationship) -> int:
    return _json_size(rel.properties) + len(rel.src_native_id) + len(rel.dst_native_id) + 64


def _reject(result: ScopeResult, record: object, exc: Exception, limits: RunnerLimits) -> int:
    """Record a rejection. Returns the bytes now held for it (the kept native ID)."""
    result.rejected += 1
    held = 0
    if isinstance(record, AssetRecord):
        native_id = usable_native_id(record, limits)
        if native_id is None:
            result.unsafe_to_delete = True
        else:
            result.rejected_ids.add(native_id)
            held = len(native_id)
    elif not isinstance(record, RelationshipRecord):
        result.unsafe_to_delete = True  # unknown record: it could have been any asset
    if result.rejected <= _MAX_LOGGED_REJECTIONS:
        _log.warning("record_rejected", scope=result.scope.id, reason=clean_text(str(exc), 200))
    return held


def _accept_asset(result: ScopeResult, asset: CollectedAsset, seen: set[str]) -> None:
    if asset.native_id in seen:
        result.duplicates += 1  # e.g. the same item on two pages: keep the first
        return
    seen.add(asset.native_id)
    result.assets.append(asset)


async def _collect_scope(
    connector: Connector,
    scope: Scope,
    *,
    provider: str,
    rules: RedactionRules,
    hmac_key: bytes,
    limits: RunnerLimits,
    budget: _Budget,
) -> ScopeResult:
    result = ScopeResult(scope=scope)
    seen: set[str] = set()
    scope_bytes = 0
    records = 0
    over_budget = "scope returned more data than allowed"
    try:
        async with timeout(limits.scope_timeout_seconds):
            async for item in connector.collect(scope):
                record: object = item  # untrusted: the declared type isn't enforced at runtime
                records += 1  # duplicates and rejects count: they cost work and memory too
                if records > limits.max_records_per_scope:
                    msg = "scope returned more records than allowed"
                    raise ConnectorError(msg)
                size = 0
                try:
                    if isinstance(record, AssetRecord):
                        asset = sanitise_asset(
                            record,
                            scope=scope,
                            provider=provider,
                            rules=rules,
                            hmac_key=hmac_key,
                            limits=limits,
                        )
                        size = _asset_size(asset)
                        _accept_asset(result, asset, seen)
                    elif isinstance(record, RelationshipRecord):
                        rel = sanitise_relationship(record, limits, rules=rules, hmac_key=hmac_key)
                        size = _relationship_size(rel)
                        result.relationships.append(rel)
                    else:
                        msg = "unknown record type"
                        raise RecordRejectedError(msg)
                except (
                    RecordRejectedError,
                    TypeError,
                    ValueError,
                    UnicodeError,
                    AttributeError,
                ) as exc:
                    size = _reject(result, record, exc, limits)
                scope_bytes += size
                if not budget.charge(size) or scope_bytes > limits.max_bytes_per_scope:
                    raise ConnectorError(over_budget)
    except ApiNotAllowedError as exc:
        _log.error("read_only_violation", scope=scope.id, api=str(exc.api))
        return ScopeResult(scope=scope, error=exc.safe_message, read_only_violation=True)
    except Exception as exc:
        # Unexpected errors log their type only: messages can carry raw provider data.
        detail = clean_text(exc.safe_message) if isinstance(exc, ConnectorError) else None
        _log.warning("scope_failed", scope=scope.id, error_type=type(exc).__name__, detail=detail)
        return ScopeResult(scope=scope, error=safe_reason(exc))
    # Edges belong to the scope that yielded them, so their source must be one of its assets.
    own = {a.native_id for a in result.assets} | result.rejected_ids
    kept = [r for r in result.relationships if r.src_native_id in own]
    result.rejected += len(result.relationships) - len(kept)
    result.relationships = kept
    return result


async def collect_all(
    connector: Connector,
    scopes: Sequence[Scope],
    *,
    provider: str,
    rules: RedactionRules,
    hmac_key: bytes,
    limits: RunnerLimits | None = None,
) -> list[ScopeResult]:
    """Collect every scope with bounded concurrency. Never raises for a single scope; raises
    :class:`ScopeDiscoveryError` if the scope list itself is unusable."""
    limits = limits or RunnerLimits()
    scopes = validate_scopes(scopes, limits)
    semaphore = Semaphore(limits.max_concurrent_scopes)
    budget = _Budget(
        remaining_bytes=limits.max_bytes_per_scan,
        remaining_records=limits.max_records_per_scan,
    )

    async def run(scope: Scope) -> ScopeResult:
        async with semaphore:
            return await _collect_scope(
                connector,
                scope,
                provider=provider,
                rules=rules,
                hmac_key=hmac_key,
                limits=limits,
                budget=budget,
            )

    results = list(await gather(*(run(scope) for scope in scopes)))
    # The same native ID from two scopes (e.g. a global resource listed per region): the
    # first successful scope owns it; later copies are dropped, never stored twice.
    owners: set[str] = set()
    for result in results:
        if not result.ok:
            continue
        unique = [a for a in result.assets if a.native_id not in owners]
        result.duplicates += len(result.assets) - len(unique)
        owners |= {a.native_id for a in unique}
        result.assets = unique
    return results
