"""``skyline-secrets-init``: create the Docker Compose stack's secrets, once.

Runs as a one-shot container before anything else and writes into the ``secrets`` volume,
one directory per consumer, so each service mounts only its own directory (read-only,
Compose ``volume.subpath``):

=============  ================================================================  =====
directory      files                                                             owner
=============  ================================================================  =====
``postgres``   ``superuser_password``, ``skyline_{owner,api,worker}.verifier``   999
``migrate``    ``db_password`` (owner role), ``bootstrap_admin_password``,       10001
               ``kek.json``
``api``        ``db_password``, ``session_key``, ``kek.json``                    10001
``worker``     ``db_password``, ``kek.json``                                     10001
``admin``      ``bootstrap_admin_password`` (for the operator to read once)      root
=============  ================================================================  =====

* Existing files are never overwritten, so re-running is safe. To start over, remove the
  volume (``docker compose down -v``), which also wipes the database.
* No value is ever printed or logged. Files are 0400, directories 0500.
* Database passwords reach PostgreSQL only as SCRAM-SHA-256 verifiers (see
  ``deploy/compose/postgres/initdb/10-skyline-roles.sh``).
* The API's KEK copy is what makes encrypt-only a database rule rather than a cryptographic
  one with the local provider (THREAT_MODEL R8); production should use KMS.
"""

from __future__ import annotations

import argparse
import functools
import os
import secrets
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Final

from skyline_core.crypto import create_kek_file
from skyline_core.db.roles import scram_sha256_verifier

POSTGRES_UID: Final = 999  # the postgres user in the official image
APP_UID: Final = 10001  # the skyline user in our images
ROOT_UID: Final = 0


if sys.platform == "win32":  # the container is Linux; tests patch this

    def _chown(path: Path, uid: int) -> None:
        del path, uid
        raise OSError("skyline-secrets-init needs POSIX ownership")

else:

    def _chown(path: Path, uid: int) -> None:
        os.chown(path, uid, uid)


def _password() -> bytes:
    return secrets.token_urlsafe(32).encode()


def _ensure_dir(path: Path, uid: int) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _chown(path, uid)
    path.chmod(0o500)


def _secret(path: Path, uid: int, make: Callable[[], bytes]) -> bytes:
    """Return the file's bytes, creating it with ``make()`` first if it doesn't exist."""
    if path.exists():
        return path.read_bytes()
    value = make()
    parent_mode = path.parent.stat().st_mode
    path.parent.chmod(0o700)  # writable just long enough to add the file
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
        _chown(path, uid)
    finally:
        path.parent.chmod(parent_mode & 0o777)
    return value


def _verifier(password: bytes) -> bytes:
    return scram_sha256_verifier(password.decode()).encode()


def _new_kek() -> bytes:
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "kek.json"
        create_kek_file(path)
        return path.read_bytes()


def initialise(root: Path) -> list[str]:
    """Create whatever is missing under ``root``. Returns the relative paths it created."""
    before = {p for p in root.rglob("*") if p.is_file()} if root.exists() else set()
    dirs = {
        "postgres": POSTGRES_UID,
        "migrate": APP_UID,
        "api": APP_UID,
        "worker": APP_UID,
        "admin": ROOT_UID,
    }
    for name, uid in dirs.items():
        _ensure_dir(root / name, uid)

    passwords = {
        "skyline_owner": _secret(root / "migrate" / "db_password", APP_UID, _password),
        "skyline_api": _secret(root / "api" / "db_password", APP_UID, _password),
        "skyline_worker": _secret(root / "worker" / "db_password", APP_UID, _password),
    }
    for role, password in passwords.items():
        _secret(
            root / "postgres" / f"{role}.verifier",
            POSTGRES_UID,
            functools.partial(_verifier, password),
        )
    _secret(root / "postgres" / "superuser_password", POSTGRES_UID, _password)

    admin = _secret(
        root / "admin" / "bootstrap_admin_password",
        ROOT_UID,
        lambda: secrets.token_urlsafe(18).encode(),
    )
    _secret(root / "migrate" / "bootstrap_admin_password", APP_UID, lambda: admin)

    kek = _secret(root / "migrate" / "kek.json", APP_UID, _new_kek)
    for name in ("api", "worker"):
        _secret(root / name / "kek.json", APP_UID, lambda: kek)
    _secret(root / "api" / "session_key", APP_UID, lambda: secrets.token_urlsafe(48).encode())

    after = {p for p in root.rglob("*") if p.is_file()}
    return sorted(str(p.relative_to(root)) for p in after - before)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path("/secrets"))
    args = parser.parse_args(argv)
    if os.name != "posix":
        sys.exit("skyline-secrets-init runs inside the Compose container (POSIX only)")
    created = initialise(args.root)
    # File names only, never contents.
    print(f"secrets-init: created {len(created)} file(s): {', '.join(created) or 'none'}")


if __name__ == "__main__":
    main()
