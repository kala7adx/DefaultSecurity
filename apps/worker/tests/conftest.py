"""Worker test fixtures: a migrated DB with the catalogue synced and a ready worker context."""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator, Sequence
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import insert

from skyline_checks.loader import LoadedCheck, load_checks
from skyline_core.crypto import LocalKeyProvider, SecretOpener, SecretPurpose, SecretSealer
from skyline_core.db.models import Integration, IntegrationStatus
from skyline_core.db.tenancy import system_scope, tenant_scope
from skyline_core.queue import PostgresJobQueue, VerifyIntegrationPayload
from skyline_core.secrets_store import create_redaction_key, store_secret
from skyline_frameworks.loader import load_frameworks
from skyline_worker.catalogue import sync_catalogue
from skyline_worker.context import WorkerContext
from skyline_worker.runner import Worker
from testsupport import Database, TenantFixture, create_tenant

KEYS = LocalKeyProvider({"test-kek": secrets.token_bytes(32)}, "test-kek")


@pytest.fixture(scope="session")
async def catalogue(db: Database) -> Sequence[LoadedCheck]:
    checks = load_checks()
    async with system_scope(db.factory("skyline_owner")) as session:
        await sync_catalogue(session, checks, load_frameworks())
    return checks


@pytest.fixture
async def ready_tenant(db: Database, catalogue: Sequence[LoadedCheck]) -> TenantFixture:
    del catalogue
    tenant = await create_tenant(db)
    async with tenant_scope(db.factory("skyline_owner"), tenant.id) as session:
        await create_redaction_key(session, SecretSealer(KEYS), tenant_id=tenant.id)
    return tenant


@pytest.fixture
def ctx(db: Database, catalogue: Sequence[LoadedCheck]) -> WorkerContext:
    return WorkerContext(
        engine=db.engine("skyline_worker"),
        session_factory=db.factory("skyline_worker"),
        opener=SecretOpener(KEYS),
        queue=PostgresJobQueue(),
        checks=catalogue,
    )


@pytest.fixture
async def worker(ctx: WorkerContext, db: Database) -> AsyncIterator[Worker]:
    await drain_jobs(db)
    yield Worker(ctx, lease=timedelta(seconds=60), poll_seconds=0.1)


async def drain_jobs(db: Database) -> None:
    """Finish leftovers from other tests so each test claims only its own jobs."""
    from sqlalchemy import update

    from skyline_core.db.models import Job

    async with system_scope(db.factory("skyline_worker")) as session:
        await session.execute(
            update(Job)
            .where(Job.status.in_(["queued", "running"]))
            .values(status="succeeded", lease_expires_at=None)
        )


async def add_fake_integration(
    db: Database, tenant: TenantFixture, config: dict[str, Any] | None = None
) -> UUID:
    """What the API does: seal a generated credential, insert, enqueue verification."""
    integration_id = uuid4()
    async with tenant_scope(db.factory("skyline_api"), tenant.id) as session:
        secret_id = await store_secret(
            session,
            SecretSealer(KEYS),
            tenant_id=tenant.id,
            purpose=SecretPurpose.INTEGRATION_CREDENTIAL,
            plaintext=json.dumps({"api_key": secrets.token_urlsafe(32)}).encode(),
        )
        await session.execute(
            insert(Integration).values(
                id=integration_id,
                tenant_id=tenant.id,
                provider="fake",
                name="Demo company",
                config=config or {},
                status=IntegrationStatus.VERIFYING.value,
                credential_secret_id=secret_id,
                created_by=tenant.admin_id,
            )
        )
        await PostgresJobQueue().enqueue(
            session,
            tenant_id=tenant.id,
            payload=VerifyIntegrationPayload(integration_id=integration_id),
        )
    return integration_id
