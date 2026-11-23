"""Alembic environment. Always driven by skyline-migrate, which passes an open connection."""

from __future__ import annotations

from alembic import context
from sqlalchemy.engine import Connection

from skyline_core.db import models  # noqa: F401 - registers every table on the metadata
from skyline_core.db.base import SCHEMA, Base


def _include_name(name: str | None, type_: str, _parent: object) -> bool:
    if type_ == "schema":
        return name == SCHEMA
    return True


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        version_table_schema=SCHEMA,
        include_schemas=True,
        include_name=_include_name,
        compare_type=True,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if not isinstance(connection, Connection):
    msg = "run migrations with skyline-migrate (an open connection is required)"
    raise RuntimeError(msg)
_run(connection)
