"""Security audit log (CLAUDE.md rule 6, ARCHITECTURE §15).

Write an entry for every privileged or security-relevant action, in the same transaction as
the action itself so the two can't diverge. ``details`` are redacted and size-capped.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from enum import StrEnum
from typing import Final, cast
from uuid import UUID

from sqlalchemy import Table, insert
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_core.db.models import ActorType, AuditLog, AuditOutcome
from skyline_core.logging import current_correlation_id
from skyline_core.redaction import redact_for_log

_MAX_DETAILS_BYTES: Final = 4096


class AuditAction(StrEnum):
    """Audited actions. Names are stable: dashboards and alerts depend on them."""

    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    LOGIN_THROTTLED = "auth.login.throttled"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGED = "auth.password.changed"  # noqa: S105 - an action name, not a secret
    PERMISSION_DENIED = "authz.denied"
    CSRF_REJECTED = "authz.csrf_rejected"
    INTEGRATION_CREATED = "integration.created"
    INTEGRATION_UPDATED = "integration.updated"
    INTEGRATION_DELETED = "integration.deleted"
    INTEGRATION_VERIFY_REQUESTED = "integration.verify_requested"
    INTEGRATION_VERIFIED = "integration.verified"
    INTEGRATION_VERIFY_FAILED = "integration.verify_failed"
    SCAN_REQUESTED = "scan.requested"
    SCAN_FINISHED = "scan.finished"
    #: A connector tried an API call outside its allowlist (ADR-0005): the scan was stopped.
    READ_ONLY_VIOLATION = "connector.read_only_violation"
    EXCEPTION_CREATED = "exception.created"
    EXCEPTION_REVOKED = "exception.revoked"
    BOOTSTRAP_COMPLETED = "platform.bootstrap"
    CATALOGUE_SYNCED = "platform.catalogue_synced"


def _sanitise_details(details: Mapping[str, object] | None) -> dict[str, object]:
    if not details:
        return {}
    cleaned = redact_for_log(dict(details))
    assert isinstance(cleaned, dict)  # noqa: S101 - redact_for_log maps dicts to dicts
    encoded = json.dumps(cleaned, default=str)
    if len(encoded.encode()) > _MAX_DETAILS_BYTES:
        return {"truncated": True}
    result: dict[str, object] = json.loads(encoded)
    return result


def _valid_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


async def record_audit(  # noqa: PLR0913 - keyword-only audit fields
    session: AsyncSession,
    *,
    action: AuditAction,
    tenant_id: UUID | None,
    actor_type: ActorType,
    actor_id: UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    target_type: str | None = None,
    target_id: str | UUID | None = None,
    details: Mapping[str, object] | None = None,
    ip: str | None = None,
) -> None:
    """Append one audit entry in the caller's transaction."""
    # inline(): no RETURNING. A returned row would also have to pass the SELECT policy, and
    # tenant-less platform rows (e.g. failed login for an unknown email) deliberately don't.
    await session.execute(
        insert(cast(Table, AuditLog.__table__))
        .inline()
        .values(
            tenant_id=tenant_id,
            actor_type=actor_type.value,
            actor_id=actor_id,
            action=action.value,
            outcome=outcome.value,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            details=_sanitise_details(details),
            ip=_valid_ip(ip),
            correlation_id=current_correlation_id(),
        )
    )
