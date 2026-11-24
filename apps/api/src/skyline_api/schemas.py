"""Request and response models. Requests reject unknown fields (SECURE_CODING §1)."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Final, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from skyline_core.db.models import ExceptionScope, Severity

#: C0 controls and DEL except tab, newline and carriage return. NUL can't be stored in
#: PostgreSQL text at all; the rest have no business in names, filters or passwords.
_CONTROL: Final = frozenset(chr(c) for c in (*range(0x20), 0x7F)) - {"\t", "\n", "\r"}


def _no_control_characters(value: str) -> str:
    if not _CONTROL.isdisjoint(value):
        msg = "control characters are not allowed"
        raise ValueError(msg)
    return value


#: Every free-text string the API accepts, in bodies and query strings, uses this type.
SafeText = Annotated[str, AfterValidator(_no_control_characters)]


class Request(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------- auth


class LoginRequest(Request):
    email: SafeText = Field(min_length=3, max_length=320)
    password: SafeText = Field(min_length=1, max_length=1024)


class ChangePasswordRequest(Request):
    current_password: SafeText = Field(min_length=1, max_length=1024)
    new_password: SafeText = Field(min_length=1, max_length=1024)


class TenantOut(Out):
    id: UUID
    slug: str
    name: str


class MeOut(BaseModel):
    user_id: UUID
    email: str
    role: str
    permissions: list[str]
    must_change_password: bool
    tenant: TenantOut


# ---------------------------------------------------------------- integrations


class IntegrationCreate(Request):
    provider: SafeText = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    name: SafeText = Field(min_length=1, max_length=200)
    config: dict[str, Any] = Field(default_factory=dict)


class IntegrationUpdate(Request):
    name: SafeText | None = Field(default=None, min_length=1, max_length=200)
    config: dict[str, Any] | None = None


class IntegrationOut(Out):
    id: UUID
    provider: str
    name: str
    config: dict[str, Any]
    status: str
    status_detail: str
    scan_interval_hours: float
    next_scan_at: datetime | None
    last_scan_at: datetime | None
    created_at: datetime


class ProviderOut(BaseModel):
    provider: str
    display_name: str
    description: str
    config_schema: dict[str, Any]


# ---------------------------------------------------------------- scans


class ScanCreate(Request):
    integration_id: UUID


class ScanOut(Out):
    id: UUID
    integration_id: UUID
    trigger: str
    status: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    stats: dict[str, Any]
    scope_errors: list[Any]


# ---------------------------------------------------------------- assets


class AssetOut(Out):
    id: UUID
    integration_id: UUID
    provider: str
    resource_type: str
    native_id: str
    name: str | None
    account_id: str | None
    region: str | None
    tags: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    deleted_at: datetime | None


class RelatedAssetOut(BaseModel):
    direction: Literal["out", "in"]
    type: str
    asset_id: UUID
    name: str | None
    resource_type: str


class AssetDetailOut(AssetOut):
    raw_config: dict[str, Any]
    relationships: list[RelatedAssetOut]
    open_findings: int


# ---------------------------------------------------------------- findings


class ControlRefOut(BaseModel):
    framework_id: str
    framework_name: str
    ref: str
    title: str
    reviewed: bool


class FindingOut(BaseModel):
    id: UUID
    check_id: str
    title: str
    severity: str
    status: str
    muted: bool
    risk_score: Decimal
    asset_id: UUID
    asset_name: str | None
    resource_type: str
    integration_id: UUID
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    reopened_count: int


class FindingEventOut(Out):
    event: str
    scan_run_id: UUID
    at: datetime


class ExceptionOut(Out):
    id: UUID
    scope_type: str
    finding_id: UUID | None
    check_id: str | None
    asset_id: UUID | None
    justification: str
    created_by: UUID
    approved_by: UUID
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class FindingDetailOut(FindingOut):
    evidence: dict[str, Any]
    check: dict[str, Any]
    controls: list[ControlRefOut]
    events: list[FindingEventOut]
    active_exception: ExceptionOut | None


class SummaryOut(BaseModel):
    open_by_severity: dict[str, int]
    open_total: int
    muted: int
    resolved: int
    by_framework: dict[str, int]


# ---------------------------------------------------------------- exceptions


class ExceptionCreate(Request):
    scope_type: ExceptionScope
    finding_id: UUID | None = None
    check_id: SafeText | None = Field(default=None, max_length=120)
    asset_id: UUID | None = None
    justification: SafeText = Field(min_length=10, max_length=2000)
    expires_at: datetime


# ---------------------------------------------------------------- catalogue / audit


class CheckOut(BaseModel):
    id: str
    version: int
    provider: str
    severity: Severity
    title: str
    enabled: bool


class FrameworkOut(Out):
    id: str
    name: str
    version: str
    source_url: str
    description: str


class ControlOut(BaseModel):
    ref: str
    title: str
    description: str
    checks: list[str]


class AuditOut(Out):
    id: int
    actor_type: str
    actor_id: UUID | None
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    correlation_id: str | None
    at: datetime
