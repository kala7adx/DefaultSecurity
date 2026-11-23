"""Declarative base, schema name and constraint naming convention."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import MetaData
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase

SCHEMA: Final = "skyline"

NAMING_CONVENTION: Final = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """All Skyline tables live in the ``skyline`` schema."""

    metadata = MetaData(schema=SCHEMA, naming_convention=NAMING_CONVENTION)
    type_annotation_map = {  # noqa: RUF012 - SQLAlchemy reads this class attribute
        UUID: PG_UUID(as_uuid=True),
        datetime: TIMESTAMP(timezone=True),
        dict[str, Any]: JSONB,
        list[Any]: JSONB,
        bytes: BYTEA,
    }
