"""Redaction of secrets in logs, audit details and collected resource configuration.

Two separate jobs share the detection rules here (CLAUDE.md rule 4, ARCHITECTURE §10):

* :func:`redact_for_log` masks secret-looking keys and values before anything is logged or
  written to the audit log. It is deliberately broad.
* :func:`redact_raw_config` replaces secret-bearing fields of collected cloud configuration
  with ``{"redacted": true, "hmac": "<hex>"}`` before storage. The HMAC (keyed per tenant)
  still lets Skyline detect a change without storing the value, and unlike a bare hash it
  cannot be brute-forced offline for low-entropy secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final

from skyline_core.types import JSON

REDACTED: Final = "[REDACTED]"
MAX_DEPTH: Final = 32

_NON_ALNUM: Final = re.compile(r"[^a-z0-9]")

# Log/audit field names: a value is never logged if the normalised key (lower-case, only
# letters and digits, so "DB_PASSWORD", "db-password" and "dbPassword" all match) contains
# one of these, or equals one of the exact names.
_LOG_KEY_PARTS: Final = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "cookie",
    "apikey",
    "accesskey",
    "privatekey",
    "accountkey",
    "credential",
    "signature",
    "csrf",
    "userdata",
    "connectionstring",
    "plaintext",
    "ciphertext",
    "wrappeddek",
    "clientassertion",
    "sharedaccess",
)
_LOG_KEY_EXACT: Final = frozenset(
    {"key", "env", "environment", "auth", "session", "sig", "dsn", "kek", "dek", "pwd"}
)

# Secret-bearing raw-config keys, whatever the provider: EXACT normalised names only.
# Substring matching would hide fields checks need (HttpTokens, PasswordPolicy,
# PasswordLastUsed, AccessKeyMetadata, SecretArn ...). Providers add their own exact names or
# key paths through RedactionRules. Deliberately no bare "key": AWS tag lists use Key/Value.
_CONFIG_SECRET_KEYS: Final = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "secrets",
        "clientsecret",
        "secretvalue",
        "secretstring",
        "secretaccesskey",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "authtoken",
        "sessiontoken",
        "bearertoken",
        "apikey",
        "apitoken",
        "privatekey",
        "privatekeypem",
        "connectionstring",
        "connectionstrings",
        "credentials",
        "userdata",
        "environment",
        "environmentvariables",
        "env",
        "sastoken",
        "accountkey",
        "primarykey",
        "secondarykey",
        "sharedaccesskey",
    }
)

#: Strings longer than this are truncated before logging and treated as secret-bearing in
#: raw config. Bounds the work the value patterns can be made to do.
MAX_LOG_STRING: Final = 8 * 1024
MAX_CONFIG_STRING: Final = 32 * 1024

_KEY_NAME_ALTERNATION = (
    r"(?:password|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key"
    r"|account[-_]?key|signature|sig|credential)"
)


@dataclass(frozen=True, slots=True)
class _ValuePattern:
    """A secret shape. With ``keep_prefix``, group 1 (a key name or URL scheme) is kept."""

    regex: re.Pattern[str]
    keep_prefix: bool = False
    suffix: str = ""


# Every pattern starts at a literal (a keyword, a fixed prefix or a bounded scheme), so the
# work per string is linear; there is no unbounded lazy prefix to backtrack over (ReDoS).
_VALUE_PATTERNS: Final = (
    _ValuePattern(
        re.compile(
            r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----.*?"
            r"(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)",
            re.S,
        )
    ),
    _ValuePattern(re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    _ValuePattern(re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    _ValuePattern(re.compile(r"(?i)\b(?:bearer|basic)\s{1,5}[A-Za-z0-9._~+/=-]{8,}")),
    # Vendor token formats (GitHub, Slack, Stripe, Google API keys).
    _ValuePattern(re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    _ValuePattern(re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    _ValuePattern(re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}")),
    _ValuePattern(re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    # key=value, key: value, "key": "value", \"key\": \"value\", ?key=value&, Key=Value;
    # Quoted values are consumed up to the closing quote (so "hunter 22" leaks nothing).
    # (?<![:/]) keeps ARN and path segments such as "...:secret:prod-db" out of it.
    _ValuePattern(
        re.compile(
            r"(?i)((?<![:/])" + _KEY_NAME_ALTERNATION + r"\\?[\"']?\s{0,5}[:=]\s{0,5})"
            r"(?:\\\"[^\"\\]{0,1024}\\\"|\"[^\"\n]{0,1024}\"|'[^'\n]{0,1024}'"
            r"|[^\s&;,'\"}\]\\]{1,1024})"
        ),
        keep_prefix=True,
    ),
    _ValuePattern(
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,30}://)[^/\s:@]{1,256}:[^/\s@]{1,256}@"),
        keep_prefix=True,
        suffix="@",
    ),
)


def _mask(value: str, replacement: Callable[[str], str]) -> str:
    for pattern in _VALUE_PATTERNS:

        def substitute(match: re.Match[str], p: _ValuePattern = pattern) -> str:
            prefix = match.group(1) if p.keep_prefix else ""
            return prefix + replacement(match.group(0)) + p.suffix

        value = pattern.regex.sub(substitute, value)
    return value


def _normalise_key(key: str) -> str:
    return _NON_ALNUM.sub("", key.lower())


def _mask_string(value: str) -> str:
    if len(value) > MAX_LOG_STRING:
        value = value[:MAX_LOG_STRING] + "...[truncated]"
    return _mask(value, lambda _match: REDACTED)


def contains_secret_pattern(value: str) -> bool:
    """True if ``value`` contains something shaped like a credential."""
    return any(pattern.regex.search(value) for pattern in _VALUE_PATTERNS)


def is_sensitive_log_key(key: str) -> bool:
    """True if a log/audit field with this name must never carry its value."""
    normalised = _normalise_key(key)
    return normalised in _LOG_KEY_EXACT or any(part in normalised for part in _LOG_KEY_PARTS)


def redact_for_log(value: object, *, _depth: int = 0) -> object:
    """Return a copy of ``value`` that is safe to log: secret keys and values are masked.

    Unknown object types are rendered with ``repr`` and then pattern-masked, so a stray object
    can never smuggle a raw secret into a log line.
    """
    if _depth > MAX_DEPTH:
        return REDACTED
    if value is None or isinstance(value, str | bool | int | float):
        return _mask_string(value) if isinstance(value, str) else value
    if isinstance(value, Mapping):
        out: dict[str, object] = {}
        for key, item in value.items():
            name = str(key)
            out[name] = (
                REDACTED if is_sensitive_log_key(name) else redact_for_log(item, _depth=_depth + 1)
            )
        return out
    if isinstance(value, list | tuple | set | frozenset):
        return [redact_for_log(item, _depth=_depth + 1) for item in value]
    if isinstance(value, bytes | bytearray | memoryview):
        return f"<{len(value)} bytes>"
    return _mask_string(repr(value))


def canonical_json(value: JSON) -> bytes:
    """Deterministic JSON encoding used for hashing and HMACs."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def config_hash(value: JSON) -> bytes:
    """SHA-256 of the canonical JSON of (already redacted) configuration, for change detection."""
    return hashlib.sha256(canonical_json(value)).digest()


@dataclass(frozen=True, slots=True)
class RedactionRules:
    """Extra secret-bearing raw-config keys for one provider (on top of the generic ones).

    Keys are compared after normalisation (lower-case, letters and digits only) and must
    match exactly.
    """

    secret_keys: frozenset[str] = field(default_factory=frozenset)

    def is_secret_key(self, key: str) -> bool:
        normalised = _normalise_key(key)
        return normalised in _CONFIG_SECRET_KEYS or normalised in self.secret_keys

    @classmethod
    def for_keys(cls, keys: Iterable[str]) -> RedactionRules:
        return cls(secret_keys=frozenset(_normalise_key(k) for k in keys if _normalise_key(k)))


class RedactionDepthError(ValueError):
    """Configuration nested deeper than :data:`MAX_DEPTH`; the record is rejected."""


def _span_tag(span: str, hmac_key: bytes) -> str:
    return hmac.new(hmac_key, span.encode(), hashlib.sha256).hexdigest()[:16]


def _redacted_marker(value: JSON, hmac_key: bytes) -> JSON:
    digest = hmac.new(hmac_key, canonical_json(value), hashlib.sha256).hexdigest()
    return {"redacted": True, "hmac": digest}


def redact_raw_config(
    value: JSON, *, rules: RedactionRules, hmac_key: bytes, _depth: int = 0
) -> JSON:
    """Replace secret-bearing fields with HMAC markers and mask secret-shaped spans.

    Raises :class:`RedactionDepthError` if nesting exceeds :data:`MAX_DEPTH`.
    """
    if _depth > MAX_DEPTH:
        msg = "configuration is nested too deeply"
        raise RedactionDepthError(msg)
    if isinstance(value, str):
        if len(value) > MAX_CONFIG_STRING:
            return _redacted_marker(value, hmac_key)
        # Mask only the secret-shaped spans, so a policy document stays readable for checks.
        # Each span becomes a keyed HMAC tag: changes are detectable, values aren't guessable.
        return _mask(value, lambda span: f"[REDACTED:{_span_tag(span, hmac_key)}]")
    if isinstance(value, Mapping):
        out: dict[str, JSON] = {}
        for key, item in value.items():
            if rules.is_secret_key(key) and item is not None:
                out[key] = _redacted_marker(item, hmac_key)
            else:
                out[key] = redact_raw_config(
                    item, rules=rules, hmac_key=hmac_key, _depth=_depth + 1
                )
        return out
    if isinstance(value, list):
        return [
            redact_raw_config(i, rules=rules, hmac_key=hmac_key, _depth=_depth + 1) for i in value
        ]
    return value
