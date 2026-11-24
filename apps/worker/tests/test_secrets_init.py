"""skyline-secrets-init: complete, idempotent, never overwrites, verifiers only for Postgres."""

from __future__ import annotations

from pathlib import Path

import pytest

from skyline_core.crypto import LocalKeyProvider
from skyline_worker import secrets_init


@pytest.fixture(autouse=True)
def _no_chown(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(secrets_init, "_chown", lambda path, uid: calls.append((path.name, uid)))
    return calls


def test_creates_every_file_once(tmp_path: Path, _no_chown: list[tuple[str, int]]) -> None:
    created = secrets_init.initialise(tmp_path)
    assert {c.replace("\\", "/") for c in created} == {
        "postgres/superuser_password",
        "postgres/skyline_owner.verifier",
        "postgres/skyline_api.verifier",
        "postgres/skyline_worker.verifier",
        "migrate/db_password",
        "migrate/bootstrap_admin_password",
        "migrate/kek.json",
        "api/db_password",
        "api/session_key",
        "api/kek.json",
        "worker/db_password",
        "worker/kek.json",
        "admin/bootstrap_admin_password",
    }
    snapshot = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert secrets_init.initialise(tmp_path) == []  # idempotent
    assert {p: p.read_bytes() for p in snapshot} == snapshot  # nothing overwritten
    # Ownership: Postgres files to the postgres uid, app files to the app uid.
    owners = dict(_no_chown)
    assert owners["superuser_password"] == secrets_init.POSTGRES_UID
    assert owners["session_key"] == secrets_init.APP_UID


def test_postgres_gets_verifiers_not_passwords(tmp_path: Path) -> None:
    secrets_init.initialise(tmp_path)
    for role, consumer in (("skyline_api", "api"), ("skyline_worker", "worker")):
        verifier = (tmp_path / "postgres" / f"{role}.verifier").read_text()
        password = (tmp_path / consumer / "db_password").read_text()
        assert verifier.startswith("SCRAM-SHA-256$4096:")
        assert password not in verifier
    postgres_files = b"".join(p.read_bytes() for p in (tmp_path / "postgres").iterdir())
    assert (tmp_path / "api" / "db_password").read_bytes() not in postgres_files


def test_kek_and_admin_password_are_shared_and_usable(tmp_path: Path) -> None:
    secrets_init.initialise(tmp_path)
    keks = {(tmp_path / d / "kek.json").read_bytes() for d in ("migrate", "api", "worker")}
    assert len(keks) == 1
    LocalKeyProvider.from_file(tmp_path / "api" / "kek.json")  # a valid KEK file
    assert (tmp_path / "admin" / "bootstrap_admin_password").read_bytes() == (
        tmp_path / "migrate" / "bootstrap_admin_password"
    ).read_bytes()
    assert len((tmp_path / "api" / "session_key").read_bytes()) >= 48
