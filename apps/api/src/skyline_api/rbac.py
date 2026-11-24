"""Role-based access control (ARCHITECTURE §9). Deny by default."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final

from skyline_core.db.models import Role


class Permission(StrEnum):
    SELF = "session:self"  # own session and profile (every signed-in user)
    FINDINGS_READ = "findings:read"
    ASSETS_READ = "assets:read"
    FRAMEWORKS_READ = "frameworks:read"
    INTEGRATIONS_READ = "integrations:read"
    SCANS_RUN = "scans:run"
    INTEGRATIONS_WRITE = "integrations:write"
    ONBOARDING_START = "onboarding:start"
    EXCEPTIONS_WRITE = "exceptions:write"
    AUDIT_READ = "audit:read"
    USERS_MANAGE = "users:manage"


_READ: Final = frozenset(
    {
        Permission.SELF,
        Permission.FINDINGS_READ,
        Permission.ASSETS_READ,
        Permission.FRAMEWORKS_READ,
        Permission.INTEGRATIONS_READ,
    }
)

ROLE_PERMISSIONS: Final[Mapping[Role, frozenset[Permission]]] = {
    Role.VIEWER: _READ,
    Role.ANALYST: _READ | {Permission.SCANS_RUN},
    Role.ADMIN: frozenset(Permission),
}


def permissions_for(role: str) -> frozenset[Permission]:
    """Permissions of a role name; unknown roles get nothing."""
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()
