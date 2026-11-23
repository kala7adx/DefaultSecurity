"""The fake cloud: a small, deterministic company used by Phase 0 and the demo.

Seeded so that exactly five checks fail out of the box, each fixable with one
``simulate_fixes`` entry:

=====================  ========================================  ===================
Resource               Problem                                   Fix
=====================  ========================================  ===================
vm-web-01              public IP + internet-open security group  remove_public_ip
sg-web-open            SSH/RDP open to 0.0.0.0/0 and ::/0        close_admin_ports
fake-customer-exports  no default encryption                     encrypt_bucket
alice.admin            administrator without MFA                 enable_mfa
vm-web-01              operating system past end of support      upgrade_os
=====================  ========================================  ===================

Everything else (vm-app-01, sg-app-tight, fake-app-logs, bob.ops, carol.viewer) passes.
"""

from __future__ import annotations

import copy
from collections.abc import Iterable
from typing import Any, Final

from skyline_connectors.fake.models import FakeFix

ACCOUNT_ID: Final = "fake-acct-001"
REGIONS: Final = ("fake-north-1", "fake-south-1")

_INSTANCES: Final[list[dict[str, Any]]] = [
    {
        "id": "vm-web-01",
        "region": "fake-north-1",
        "name": "web-frontend",
        "public_ip": "203.0.113.10",
        "private_ip": "10.0.1.10",
        "os": {"name": "FakeOS", "version": "14.04", "end_of_support": "2024-04-30"},
        "security_groups": ["sg-web-open"],
        "role": "role-web",
        # Secret-bearing field: redacted before storage, kept as an HMAC marker.
        "user_data": "#!/bin/sh\n/opt/app/configure --db-password-file /run/secrets/db\n",
        "tags": {"env": "prod", "team": "web"},
    },
    {
        "id": "vm-app-01",
        "region": "fake-north-1",
        "name": "app-backend",
        "public_ip": None,
        "private_ip": "10.0.2.20",
        "os": {"name": "FakeOS", "version": "24.04", "end_of_support": "2034-04-30"},
        "security_groups": ["sg-app-tight"],
        "role": None,
        "user_data": None,
        "tags": {"env": "prod", "team": "app"},
    },
]

_SECURITY_GROUPS: Final[list[dict[str, Any]]] = [
    {
        "id": "sg-web-open",
        "region": "fake-north-1",
        "name": "web-open",
        "ingress": [
            {"protocol": "tcp", "from_port": 443, "to_port": 443, "sources": ["0.0.0.0/0"]},
            {"protocol": "tcp", "from_port": 22, "to_port": 22, "sources": ["0.0.0.0/0"]},
            {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "sources": ["::/0"]},
        ],
        "tags": {"env": "prod"},
    },
    {
        "id": "sg-app-tight",
        "region": "fake-north-1",
        "name": "app-tight",
        "ingress": [
            {"protocol": "tcp", "from_port": 8080, "to_port": 8080, "sources": ["10.0.0.0/16"]},
        ],
        "tags": {"env": "prod"},
    },
]

_BUCKETS: Final[list[dict[str, Any]]] = [
    {
        "id": "fake-customer-exports",
        "region": "fake-north-1",
        "encryption": None,
        "versioning": False,
        "tags": {"data": "customer", "env": "prod"},
    },
    {
        "id": "fake-app-logs",
        "region": "fake-south-1",
        "encryption": {"algorithm": "AES256"},
        "versioning": True,
        "tags": {"data": "logs"},
    },
]

_ROLES: Final[list[dict[str, Any]]] = [
    {"id": "role-admin", "name": "Administrators", "admin": True},
    {"id": "role-readonly", "name": "ReadOnly", "admin": False},
    {"id": "role-web", "name": "WebServer", "admin": False},
]

_USERS: Final[list[dict[str, Any]]] = [
    {"id": "alice.admin", "display_name": "Alice", "mfa_enabled": False, "roles": ["role-admin"]},
    {"id": "bob.ops", "display_name": "Bob", "mfa_enabled": True, "roles": ["role-admin"]},
    {
        "id": "carol.viewer",
        "display_name": "Carol",
        "mfa_enabled": False,
        "roles": ["role-readonly"],
    },
]


class FakeCloud:
    """An in-memory view of the fake company with the requested fixes applied."""

    def __init__(self, fixes: Iterable[FakeFix] = ()) -> None:
        fixes = set(fixes)
        self.instances = copy.deepcopy(_INSTANCES)
        self.security_groups = copy.deepcopy(_SECURITY_GROUPS)
        self.buckets = copy.deepcopy(_BUCKETS)
        self.roles = copy.deepcopy(_ROLES)
        self.users = copy.deepcopy(_USERS)
        web = self.instances[0]
        if "remove_public_ip" in fixes:
            web["public_ip"] = None
        if "upgrade_os" in fixes:
            web["os"] = {"name": "FakeOS", "version": "24.04", "end_of_support": "2034-04-30"}
        if "close_admin_ports" in fixes:
            group = self.security_groups[0]
            group["ingress"] = [r for r in group["ingress"] if r["from_port"] not in (22, 3389)]
        if "encrypt_bucket" in fixes:
            self.buckets[0]["encryption"] = {"algorithm": "AES256"}
        if "enable_mfa" in fixes:
            self.users[0]["mfa_enabled"] = True

    def in_region(self, items: list[dict[str, Any]], region: str) -> list[dict[str, Any]]:
        return [item for item in items if item["region"] == region]
