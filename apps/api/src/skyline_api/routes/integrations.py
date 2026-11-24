"""Integrations: list, create (fake only in Phase 0), update, re-verify, delete."""

from __future__ import annotations

import copy
import json
import secrets
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Query, Response
from pydantic import ValidationError
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from skyline_api.auth import Principal, ServicesDep, TenantDbDep, require
from skyline_api.errors import ApiError, not_found
from skyline_api.rbac import Permission
from skyline_api.schemas import (
    IntegrationCreate,
    IntegrationOut,
    IntegrationUpdate,
    Page,
    ProviderOut,
)
from skyline_api.services import Services
from skyline_connectors.catalog import PROVIDERS, CredentialMode, provider_info
from skyline_core.audit import AuditAction, record_audit
from skyline_core.crypto import SecretPurpose
from skyline_core.db.models import ActorType, Integration, IntegrationStatus, Secret
from skyline_core.queue import VerifyIntegrationPayload
from skyline_core.secrets_store import store_secret

router = APIRouter(prefix="/api/v1", tags=["integrations"])


def _out(row: Integration) -> IntegrationOut:
    return IntegrationOut(
        id=row.id,
        provider=row.provider,
        name=row.name,
        config=row.config,
        status=row.status,
        status_detail=row.status_detail,
        scan_interval_hours=row.scan_interval.total_seconds() / 3600,
        next_scan_at=row.next_scan_at,
        last_scan_at=row.last_scan_at,
        created_at=row.created_at,
    )


def _validated_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    info = provider_info(provider)
    if info is None:
        raise ApiError(422, "unknown_provider", "This provider is not supported")
    try:
        return info.config_model.model_validate(config).model_dump(mode="json")
    except ValidationError:
        raise ApiError(
            422, "invalid_config", "The integration configuration is not valid"
        ) from None


async def _get(db: AsyncSession, tenant_id: UUID, integration_id: UUID) -> Integration:
    row = (
        await db.execute(
            select(Integration)
            .where(
                Integration.tenant_id == tenant_id,
                Integration.id == integration_id,
                Integration.deleted_at.is_(None),
            )
            # Re-read after Core UPDATEs and trigger changes, not the identity-map copy.
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if row is None:
        raise not_found("integration")
    return row


async def _enqueue_verify(
    svc: Services, db: AsyncSession, tenant_id: UUID, integration_id: UUID
) -> None:
    """Queue a credential check unless one is already waiting (it will load the latest
    configuration when it runs), so repeated clicks can't flood the shared queue."""
    try:
        async with db.begin_nested():
            await svc.queue.enqueue(
                db,
                tenant_id=tenant_id,
                payload=VerifyIntegrationPayload(integration_id=integration_id),
            )
    except IntegrityError as exc:
        if "uq_jobs_one_queued_verify" not in str(exc):
            raise


@router.get("/providers")
async def providers(
    svc: ServicesDep,
    _p: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_READ))],
) -> list[ProviderOut]:
    return [
        ProviderOut(
            provider=info.provider,
            display_name=info.display_name,
            description=info.description,
            config_schema=info.config_model.model_json_schema(),
        )
        for info in PROVIDERS.values()
        if not info.demo_only or svc.settings.demo_providers_allowed
    ]


@router.get("/integrations")
async def list_integrations(
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_READ))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
) -> Page[IntegrationOut]:
    base = select(Integration).where(
        Integration.tenant_id == tdb.principal.tenant_id, Integration.deleted_at.is_(None)
    )
    async with tdb.transaction() as db:
        total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
        rows = (
            await db.execute(base.order_by(Integration.created_at).limit(limit).offset(offset))
        ).scalars()
        return Page(items=[_out(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/integrations/{integration_id}")
async def get_integration(
    integration_id: UUID,
    tdb: TenantDbDep,
    _p: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_READ))],
) -> IntegrationOut:
    async with tdb.transaction() as db:
        return _out(await _get(db, tdb.principal.tenant_id, integration_id))


@router.post("/integrations", status_code=201)
async def create_integration(
    body: IntegrationCreate,
    svc: ServicesDep,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_WRITE))],
) -> IntegrationOut:
    config = _validated_config(body.provider, body.config)  # unknown provider -> 422 first
    info = provider_info(body.provider)
    if (
        info is None
        or info.credential_mode is not CredentialMode.GENERATED  # real ones: Phase 1+
        or (info.demo_only and not svc.settings.demo_providers_allowed)
    ):
        raise ApiError(422, "unsupported_provider", "This provider can't be added")
    integration_id = uuid4()
    async with tdb.transaction() as db:
        # Encrypt-only: the API seals the generated credential and can never read it back.
        secret_id = await store_secret(
            db,
            svc.sealer,
            tenant_id=principal.tenant_id,
            purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
            plaintext=json.dumps({"api_key": secrets.token_urlsafe(32)}).encode(),
        )
        await db.execute(
            insert(Integration).values(
                id=integration_id,
                tenant_id=principal.tenant_id,
                provider=body.provider,
                name=body.name,
                config=config,
                status=IntegrationStatus.VERIFYING.value,
                credential_secret_id=secret_id,
                created_by=principal.user_id,
            )
        )
        await _enqueue_verify(svc, db, principal.tenant_id, integration_id)
        await record_audit(
            db,
            action=AuditAction.INTEGRATION_CREATED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            target_type="integration",
            target_id=integration_id,
            details={"provider": body.provider, "name": body.name},
            ip=principal.ip,
        )
        return _out(await _get(db, principal.tenant_id, integration_id))


@router.patch("/integrations/{integration_id}")
async def update_integration(
    integration_id: UUID,
    body: IntegrationUpdate,
    svc: ServicesDep,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_WRITE))],
) -> IntegrationOut:
    async with tdb.transaction() as db:
        row = await _get(db, principal.tenant_id, integration_id)
        values: dict[str, Any] = {"updated_at": func.now()}
        if body.name is not None:
            values["name"] = body.name
        config_changed = body.config is not None
        if body.config is not None:
            values["config"] = _validated_config(row.provider, body.config)
        # Non-secret values only (config is validated against the provider's config model,
        # which holds no credentials), so a role or scope change is traceable later. Taken
        # before the UPDATE, which also refreshes ``row`` in the session.
        changes = {
            key: {"before": copy.deepcopy(getattr(row, key)), "after": values[key]}
            for key in ("name", "config")
            if key in values and getattr(row, key) != values[key]
        }
        await db.execute(
            update(Integration)
            .where(Integration.tenant_id == principal.tenant_id, Integration.id == integration_id)
            .values(**values)
        )
        if config_changed:
            # The database sends a connected integration back to verifying (trigger);
            # re-verification then reconnects it and starts a fresh scan.
            await _enqueue_verify(svc, db, principal.tenant_id, integration_id)
        await record_audit(
            db,
            action=AuditAction.INTEGRATION_UPDATED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            target_type="integration",
            target_id=integration_id,
            details={"changes": changes},
            ip=principal.ip,
        )
        return _out(await _get(db, principal.tenant_id, integration_id))


@router.post("/integrations/{integration_id}/test", status_code=202)
async def test_integration(
    integration_id: UUID,
    svc: ServicesDep,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_WRITE))],
) -> dict[str, str]:
    async with tdb.transaction() as db:
        await _get(db, principal.tenant_id, integration_id)
        await _enqueue_verify(svc, db, principal.tenant_id, integration_id)
        await record_audit(
            db,
            action=AuditAction.INTEGRATION_VERIFY_REQUESTED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            target_type="integration",
            target_id=integration_id,
            ip=principal.ip,
        )
    return {"status": "queued"}


@router.delete("/integrations/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: UUID,
    tdb: TenantDbDep,
    principal: Annotated[Principal, Depends(require(Permission.INTEGRATIONS_WRITE))],
) -> Response:
    async with tdb.transaction() as db:
        row = await _get(db, principal.tenant_id, integration_id)
        secret_id = row.credential_secret_id
        await db.execute(
            update(Integration)
            .where(Integration.tenant_id == principal.tenant_id, Integration.id == integration_id)
            .values(
                credential_secret_id=None,
                status=IntegrationStatus.DISABLED.value,
                deleted_at=func.now(),
                next_scan_at=None,
                updated_at=func.now(),
            )
        )
        if secret_id is not None:
            # Removes the sealed credential (wrapped DEK + ciphertext) from the live
            # database. Copies remain in WAL and backups until they age out; true
            # crypto-shredding needs per-tenant KMS keys (Phase 4).
            await db.execute(
                delete(Secret).where(
                    Secret.tenant_id == principal.tenant_id, Secret.id == secret_id
                )
            )
        await record_audit(
            db,
            action=AuditAction.INTEGRATION_DELETED,
            tenant_id=principal.tenant_id,
            actor_type=ActorType.USER,
            actor_id=principal.user_id,
            target_type="integration",
            target_id=integration_id,
            details={"credential_removed": secret_id is not None},
            ip=principal.ip,
        )
    return Response(status_code=204)
