"""Session-wide pytest fixtures. Helpers live in ``testsupport``."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Iterator, Sequence

import pytest
from testcontainers.community.postgres import PostgresContainer

from skyline_checks.loader import LoadedCheck
from testsupport import (
    POSTGRES_IMAGE,
    Database,
    TenantFixture,
    create_tenant,
    prepare_database,
    sync_test_catalogue,
)


@pytest.fixture(scope="session")
def postgres_container() -> Iterator[PostgresContainer]:
    with PostgresContainer(
        POSTGRES_IMAGE,
        username="postgres",
        password=secrets.token_hex(16),
        dbname="postgres",
        driver=None,
    ) as container:
        yield container


@pytest.fixture(scope="session")
async def db(postgres_container: PostgresContainer) -> AsyncIterator[Database]:
    database = await prepare_database(
        host=postgres_container.get_container_host_ip(),
        port=int(postgres_container.get_exposed_port(5432)),
        superuser=postgres_container.username,
        superuser_password=postgres_container.password,
    )
    yield database
    await database.dispose()


@pytest.fixture
async def tenant(db: Database) -> TenantFixture:
    return await create_tenant(db)


@pytest.fixture
async def other_tenant(db: Database) -> TenantFixture:
    return await create_tenant(db)


@pytest.fixture(scope="session")
async def catalogue(db: Database) -> Sequence[LoadedCheck]:
    return await sync_test_catalogue(db)
