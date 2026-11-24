"""API test fixtures: the real app against the test database, driven through httpx."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import timedelta

import httpx
import pytest
from pydantic import SecretStr

from skyline_api.app import create_app
from skyline_api.auth import CSRF_COOKIE
from skyline_api.services import Services
from skyline_api.settings import ApiSettings
from skyline_checks.loader import LoadedCheck
from skyline_core.crypto import SecretOpener, SecretSealer
from skyline_core.db.models import Role
from skyline_core.queue import PostgresJobQueue
from skyline_core.settings import Environment
from skyline_core.types import Sensitive
from skyline_worker.context import WorkerContext
from skyline_worker.runner import Worker
from testsupport import (
    TEST_KEYS,
    Database,
    TenantFixture,
    add_redaction_key,
    create_tenant,
    reset_jobs,
)

ORIGIN = "https://skyline.test"


def api_settings(db: Database, **overrides: object) -> ApiSettings:
    values: dict[str, object] = {
        "env": Environment.TEST,
        "db_host": db.host,
        "db_port": db.port,
        "db_name": db.name,
        "db_password": SecretStr(db.passwords["skyline_api"]),
        "db_sslmode": "disable",
        "public_origin": ORIGIN,
        "session_key": SecretStr(secrets.token_urlsafe(48)),
        "demo_provider_enabled": True,
    }
    values.update(overrides)
    return ApiSettings(**values)  # type: ignore[arg-type]


def make_services(db: Database, settings: ApiSettings) -> Services:
    assert settings.session_key is not None
    return Services(
        settings=settings,
        engine=db.engine("skyline_api"),
        session_factory=db.factory("skyline_api"),
        sealer=SecretSealer(TEST_KEYS),
        queue=PostgresJobQueue(),
        session_key=Sensitive(settings.session_key.get_secret_value().encode()),
    )


@pytest.fixture
def settings(db: Database) -> ApiSettings:
    return api_settings(db)


@pytest.fixture
async def client(db: Database, settings: ApiSettings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings, make_services(db, settings))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("203.0.113.9", 50000)),
        base_url=ORIGIN,
        headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"},
    ) as http:
        yield http


@dataclass(frozen=True)
class User:
    tenant: TenantFixture
    password: str

    @property
    def email(self) -> str:
        return self.tenant.admin_email


async def make_user(db: Database, role: Role = Role.ADMIN, *, must_change: bool = False) -> User:
    password = secrets.token_urlsafe(18)
    tenant = await create_tenant(db, role=role, password=password)
    await add_redaction_key(db, tenant)
    if must_change:
        from sqlalchemy import update

        from skyline_core.db.models import User as UserRow
        from skyline_core.db.tenancy import system_scope

        async with system_scope(db.factory("skyline_owner")) as session:
            await session.execute(
                update(UserRow)
                .where(UserRow.id == tenant.admin_id)
                .values(must_change_password=True)
            )
    return User(tenant=tenant, password=password)


async def login(client: httpx.AsyncClient, user: User) -> httpx.Response:
    response = await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": user.password}
    )
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = client.cookies[CSRF_COOKIE]
    return response


@pytest.fixture
async def admin(db: Database, catalogue: Sequence[LoadedCheck]) -> User:
    del catalogue
    return await make_user(db)


@pytest.fixture
async def signed_in(client: httpx.AsyncClient, admin: User) -> httpx.AsyncClient:
    await login(client, admin)
    return client


@pytest.fixture
async def worker(db: Database, catalogue: Sequence[LoadedCheck]) -> Worker:
    await reset_jobs(db)
    ctx = WorkerContext(
        engine=db.engine("skyline_worker"),
        session_factory=db.factory("skyline_worker"),
        opener=SecretOpener(TEST_KEYS),
        queue=PostgresJobQueue(),
        checks=catalogue,
        demo_providers_allowed=True,
    )
    return Worker(ctx, lease=timedelta(seconds=60), poll_seconds=0.1)


async def drain(worker: Worker) -> int:
    ran = 0
    while await worker.run_once():
        ran += 1
    return ran
