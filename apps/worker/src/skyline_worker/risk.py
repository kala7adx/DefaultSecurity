"""v0 risk score (ARCHITECTURE §3): severity weight x exposure x sensitivity.

Phase 7 replaces this with graph-derived exposure, privilege reach and toxic combinations.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Final

from skyline_checks.engine import AssetView
from skyline_core.db.models import Severity

SEVERITY_WEIGHT: Final[Mapping[Severity, Decimal]] = {
    Severity.CRITICAL: Decimal(10),
    Severity.HIGH: Decimal(7),
    Severity.MEDIUM: Decimal(4),
    Severity.LOW: Decimal(1),
    Severity.INFO: Decimal(0),
}
_EXPOSED: Final = Decimal("1.5")
_SENSITIVE: Final = Decimal("1.3")
_SENSITIVE_TAGS: Final = {("env", "prod"), ("env", "production"), ("data", "customer")}


def is_internet_facing(asset: AssetView) -> bool:
    """Phase 0 heuristic: the asset has a public IP address."""
    return bool(asset.config.get("public_ip"))


def is_sensitive(asset: AssetView) -> bool:
    tags = {(k.lower(), str(v).lower()) for k, v in asset.tags.items()}
    return bool(tags & _SENSITIVE_TAGS) or "sensitive" in {k for k, _ in tags}


def risk_score(severity: Severity, asset: AssetView) -> Decimal:
    score = SEVERITY_WEIGHT[severity]
    if is_internet_facing(asset):
        score *= _EXPOSED
    if is_sensitive(asset):
        score *= _SENSITIVE
    return score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
