"""Runs a connector over its scopes and turns raw records into safe, bounded data.

Connector output is untrusted (it mirrors provider responses), so every record is validated,
size-capped and redacted here before anything is stored. Each scope succeeds or fails on its
own: a failed scope is reported with a sanitised reason and its data is left untouched.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from skyline_connectors.base import (
    AssetRecord,
    Connector,
    ConnectorError,
    RelationshipRecord,
    Scope,
)
from skyline_core.logging import get_logger
from skyline_core.redaction import (
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


@dataclass(frozen=True, slots=True)
class RunnerLimits:
    max_native_id: int = 2048
    max_name: int = 512
    max_tags: int = 100
    max_tag_key: int = 256
    max_tag_value: int = 512
    max_raw_config_bytes: int = 256 * 1024
    max_records_per_scope: int = 50_000
    scope_timeout_seconds: float = 15 * 60
    max_concurrent_scopes: int = 4


class RecordRejectedError(ValueError):
    """A record broke a validation rule or cap."""


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
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _bounded(value: str | None, limit: int, what: str) -> str | None:
    if value is not None and len(value) > limit:
        msg = f"{what} is too long"
        raise RecordRejectedError(msg)
    return value


def _clean_tags(tags: Mapping[str, str], limits: RunnerLimits) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in list(tags.items())[: limits.max_tags]:
        key_text = str(key)[: limits.max_tag_key]
        value_text = str(value)[: limits.max_tag_value]
        # Tags are a common place for people to paste secrets.
        cleaned[key_text] = "[REDACTED]" if contains_secret_pattern(value_text) else value_text
    return cleaned


def sanitise_asset(
    record: AssetRecord,
    *,
    scope: Scope,
    provider: str,
    rules: RedactionRules,
    hmac_key: bytes,
    limits: RunnerLimits,
) -> CollectedAsset:
    """Validate, cap and redact one asset record."""
    if not _RESOURCE_TYPE.match(record.resource_type) or not record.resource_type.startswith(
        f"{provider}."
    ):
        msg = "resource type is not valid for this provider"
        raise RecordRejectedError(msg)
    if record.scope_id != scope.id:
        msg = "record belongs to a different scope"
        raise RecordRejectedError(msg)
    if not record.native_id:
        msg = "native ID is empty"
        raise RecordRejectedError(msg)
    _bounded(record.native_id, limits.max_native_id, "native ID")
    try:
        size = len(json.dumps(record.raw_config, separators=(",", ":"), allow_nan=False))
        redacted = redact_raw_config(dict(record.raw_config), rules=rules, hmac_key=hmac_key)
    except (TypeError, ValueError, RedactionDepthError) as exc:
        msg = "raw configuration is not plain JSON"
        raise RecordRejectedError(msg) from exc
    if size > limits.max_raw_config_bytes:
        msg = "raw configuration is too large"
        raise RecordRejectedError(msg)
    assert isinstance(redacted, dict)  # noqa: S101 - a dict stays a dict after redaction
    return CollectedAsset(
        resource_type=record.resource_type,
        native_id=record.native_id,
        name=_bounded(record.name, limits.max_name, "name"),
        account_id=_bounded(record.account_id, 256, "account ID"),
        region=_bounded(record.region, 64, "region"),
        scope_id=scope.id,
        tags=_clean_tags(record.tags, limits),
        raw_config=redacted,
        config_hash=config_hash(redacted),
    )


def sanitise_relationship(
    record: RelationshipRecord, limits: RunnerLimits
) -> CollectedRelationship:
    if not _REL_TYPE.match(record.type):
        msg = "relationship type is not valid"
        raise RecordRejectedError(msg)
    for native_id in (record.src_native_id, record.dst_native_id):
        if not native_id or len(native_id) > limits.max_native_id:
            msg = "relationship endpoint is not valid"
            raise RecordRejectedError(msg)
    properties = dict(record.properties)
    if len(json.dumps(properties, default=str)) > 4096:  # noqa: PLR2004
        msg = "relationship properties are too large"
        raise RecordRejectedError(msg)
    return CollectedRelationship(
        record.src_native_id, record.dst_native_id, record.type, properties
    )


def safe_reason(exc: BaseException) -> str:
    """A user-safe reason for a scope failure. Unexpected errors reveal nothing."""
    if isinstance(exc, ConnectorError):
        return exc.safe_message[:300]
    if isinstance(exc, TimeoutError):
        return "collection timed out"
    return "unexpected error while collecting (see worker logs)"


async def _collect_scope(
    connector: Connector,
    scope: Scope,
    *,
    provider: str,
    rules: RedactionRules,
    hmac_key: bytes,
    limits: RunnerLimits,
) -> ScopeResult:
    result = ScopeResult(scope=scope)
    try:
        async with asyncio.timeout(limits.scope_timeout_seconds):
            async for record in connector.collect(scope):
                if len(result.assets) + len(result.relationships) >= limits.max_records_per_scope:
                    msg = "scope returned more records than allowed"
                    raise ConnectorError(msg)
                try:
                    if isinstance(record, AssetRecord):
                        result.assets.append(
                            sanitise_asset(
                                record,
                                scope=scope,
                                provider=provider,
                                rules=rules,
                                hmac_key=hmac_key,
                                limits=limits,
                            )
                        )
                    else:
                        result.relationships.append(sanitise_relationship(record, limits))
                except RecordRejectedError as exc:
                    result.rejected += 1
                    _log.warning("record_rejected", scope=scope.id, reason=str(exc))
    except Exception as exc:
        _log.warning("scope_failed", scope=scope.id, error_type=type(exc).__name__, error=str(exc))
        return ScopeResult(scope=scope, error=safe_reason(exc))
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
    """Collect every scope with bounded concurrency. Never raises for a single scope."""
    limits = limits or RunnerLimits()
    semaphore = asyncio.Semaphore(limits.max_concurrent_scopes)

    async def run(scope: Scope) -> ScopeResult:
        async with semaphore:
            return await _collect_scope(
                connector, scope, provider=provider, rules=rules, hmac_key=hmac_key, limits=limits
            )

    return list(await asyncio.gather(*(run(scope) for scope in scopes)))
