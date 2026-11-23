"""Evaluators for the fake provider's five demo checks. Pure functions, no I/O."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Final

from skyline_checks.engine import AssetView, EvalContext, Result
from skyline_checks.registry import evaluator
from skyline_core.types import JSON

INTERNET: Final = frozenset({"0.0.0.0/0", "::/0"})
ADMIN_PORTS: Final = {22: "SSH", 3389: "RDP"}


def _rules(group: AssetView) -> list[Mapping[str, JSON]]:
    ingress = group.config.get("ingress")
    if not isinstance(ingress, list):
        return []
    return [rule for rule in ingress if isinstance(rule, dict)]


def _open_to_internet(rule: Mapping[str, JSON]) -> bool:
    sources = rule.get("sources")
    return isinstance(sources, list) and any(s in INTERNET for s in sources)


def _covers(rule: Mapping[str, JSON], port: int) -> bool:
    low, high = rule.get("from_port"), rule.get("to_port")
    if rule.get("protocol") not in {"tcp", "all", "-1"}:
        return False
    if not isinstance(low, int) or not isinstance(high, int):
        return False
    return low <= port <= high


@evaluator("fake.compute.vm_public_exposure")
def vm_public_exposure(asset: AssetView, ctx: EvalContext) -> Result:
    public_ip = asset.config.get("public_ip")
    if not public_ip:
        return Result.passed(public_ip=None)
    open_groups: list[JSON] = [
        group.name or group.native_id
        for group in ctx.related(asset, "attached_to", "out")
        if any(_open_to_internet(rule) for rule in _rules(group))
    ]
    if not open_groups:
        return Result.passed(public_ip=public_ip, open_security_groups=[])
    return Result.failed(public_ip=public_ip, open_security_groups=open_groups)


@evaluator("fake.network.sg_admin_ports_open")
def sg_admin_ports_open(asset: AssetView, _ctx: EvalContext) -> Result:
    exposed: list[JSON] = []
    for rule in _rules(asset):
        if not _open_to_internet(rule):
            continue
        for port, label in ADMIN_PORTS.items():
            if _covers(rule, port):
                exposed.append({"port": port, "service": label, "sources": rule.get("sources")})
    if exposed:
        return Result.failed(exposed_admin_ports=exposed)
    return Result.passed(exposed_admin_ports=[])


@evaluator("fake.storage.bucket_encryption")
def bucket_encryption(asset: AssetView, _ctx: EvalContext) -> Result:
    encryption = asset.config.get("encryption")
    if isinstance(encryption, dict) and encryption.get("algorithm"):
        return Result.passed(algorithm=encryption["algorithm"])
    return Result.failed(default_encryption="none")


@evaluator("fake.identity.admin_without_mfa")
def admin_without_mfa(asset: AssetView, ctx: EvalContext) -> Result:
    admin_roles: list[JSON] = [
        *sorted(
            role.name or role.native_id
            for role in ctx.related(asset, "member_of", "out")
            if role.config.get("admin") is True
        )
    ]
    if not admin_roles:
        return Result.not_applicable("user has no administrative role")
    if asset.config.get("mfa_enabled") is True:
        return Result.passed(admin_roles=admin_roles, mfa_enabled=True)
    return Result.failed(admin_roles=admin_roles, mfa_enabled=False)


@evaluator("fake.compute.unsupported_os")
def unsupported_os(asset: AssetView, ctx: EvalContext) -> Result:
    os_info = asset.config.get("os")
    if not isinstance(os_info, dict) or not isinstance(os_info.get("end_of_support"), str):
        return Result.error("operating system support date is unknown")
    try:
        end = date.fromisoformat(str(os_info["end_of_support"]))
    except ValueError:
        return Result.error("operating system support date is not a valid date")
    evidence: dict[str, JSON] = {
        "os": f"{os_info.get('name', '?')} {os_info.get('version', '?')}",
        "end_of_support": end.isoformat(),
    }
    if end < ctx.now.date():
        return Result.failed(**evidence)
    return Result.passed(**evidence)
