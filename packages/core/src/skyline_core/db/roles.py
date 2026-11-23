"""Create the Skyline database roles (run once by a superuser at database bootstrap).

Compose does the same in ``deploy/compose/postgres/initdb/10-skyline-roles.sh``; managed
databases (RDS, Flexible Server, Cloud SQL) get the equivalent in Phase 4.

Passwords never reach the server in cleartext: we compute the SCRAM-SHA-256 verifier here
(RFC 7677, PostgreSQL's stored format) and send only that, so statement logs, error context or
``pg_stat_statements`` can't capture a usable password. The verifier travels as a bound value
and is quoted server-side with ``format('%L')``; no SQL is built from input.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Mapping
from typing import Final

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncConnection

from skyline_core.types import Sensitive

LOGIN_ROLES: Final = ("skyline_owner", "skyline_api", "skyline_worker")
DEFINER_ROLE: Final = "skyline_definer"
SCRAM_ITERATIONS: Final = 4096  # PostgreSQL's default scram_iterations

_UPSERT_LOGIN_ROLE = text(
    """
    DO $$
    DECLARE
        r text := current_setting('skyline.bootstrap_role');
        v text := current_setting('skyline.bootstrap_verifier');
        attrs text := 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
    BEGIN
        IF v NOT LIKE 'SCRAM-SHA-256$%' THEN
            RAISE EXCEPTION 'expected a SCRAM-SHA-256 verifier';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN ' || attrs || ' PASSWORD %L', r, v);
        ELSE
            EXECUTE format('ALTER ROLE %I LOGIN ' || attrs || ' PASSWORD %L', r, v);
        END IF;
    END $$
    """
)

_CREATE_DEFINER = text(
    """
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'skyline_definer') THEN
            CREATE ROLE skyline_definer
                NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
        END IF;
    END $$
    """
)

# The owner must be able to hand functions to the definer role (ALTER FUNCTION ... OWNER
# needs SET), but must NOT inherit its privileges or its pre-tenant RLS policies (PG 16+).
_GRANT_DEFINER_TO_OWNER = text(
    "GRANT skyline_definer TO skyline_owner WITH INHERIT FALSE, SET TRUE"
)


def scram_sha256_verifier(password: str, *, iterations: int = SCRAM_ITERATIONS) -> str:
    """PostgreSQL ``SCRAM-SHA-256$iter:salt$StoredKey:ServerKey`` for an ASCII password.

    Generated passwords are printable ASCII, for which SASLprep is the identity function.
    """
    if not password or not password.isascii() or not password.isprintable():
        msg = "generated database passwords must be printable ASCII"
        raise ValueError(msg)
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


async def create_roles(conn: AsyncConnection, passwords: Mapping[str, Sensitive[str]]) -> None:
    """Create or update the three login roles and the NOLOGIN definer role.

    ``conn`` must be a superuser (or CREATEROLE) connection inside a transaction.
    """
    for role in LOGIN_ROLES:
        verifier = scram_sha256_verifier(passwords[role].reveal())
        await conn.execute(select(func.set_config("skyline.bootstrap_role", role, True)))
        await conn.execute(select(func.set_config("skyline.bootstrap_verifier", verifier, True)))
        await conn.execute(_UPSERT_LOGIN_ROLE)
    await conn.execute(select(func.set_config("skyline.bootstrap_verifier", "", True)))
    await conn.execute(_CREATE_DEFINER)
    await conn.execute(_GRANT_DEFINER_TO_OWNER)
