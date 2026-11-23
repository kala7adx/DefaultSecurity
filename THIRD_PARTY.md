# Third-party software

Skyline is Apache-2.0. This file records the direct dependencies, the CI-only tools, and any
licence exceptions (ADR-0010). Exact versions are in `uv.lock` and `pnpm-lock.yaml`; CI checks
every transitive licence against the allowlist in `scripts/licence_allowlist.json`.

## Python runtime dependencies (direct)

| Package | Purpose | Licence |
|---|---|---|
| alembic | Database migrations | MIT |
| argon2-cffi | argon2id password hashing | MIT |
| asyncpg | PostgreSQL driver (chosen over psycopg, which is LGPL) | Apache-2.0 |
| cryptography | AES-256-GCM envelope encryption, HMAC | Apache-2.0 OR BSD-3-Clause |
| fastapi | REST API framework | MIT |
| pydantic, pydantic-settings | Validation of every external input; configuration | MIT |
| pyyaml | Check and framework catalogues (`yaml.safe_load` only) | MIT |
| sqlalchemy | Database access with bound parameters | MIT |
| structlog | Structured JSON logging with the redaction processor | MIT OR Apache-2.0 |
| uvicorn | ASGI server | BSD-3-Clause |

## Python development dependencies (direct)

| Package | Purpose | Licence |
|---|---|---|
| coverage, pytest-cov | Coverage gates | Apache-2.0, MIT |
| httpx | API test client | BSD-3-Clause |
| mypy | Static types (`--strict`) | MIT |
| pip-licenses | Licence gate | MIT |
| pytest, pytest-asyncio | Tests | MIT, Apache-2.0 |
| ruff | Lint (incl. bandit rules) and format | MIT |
| testcontainers | Real PostgreSQL in tests | Apache-2.0 |
| types-pyyaml | Type stubs | Apache-2.0 |

Notable transitive licences: `certifi` and `pathspec` are MPL-2.0 (allowed);
`typing-extensions` and `greenlet` include PSF-2.0 (owner-approved, ADR-0010);
`cffi` is MIT-0 (owner-approved).

## Web dependencies (direct)

Recorded when `apps/web` is added.

## CI-only tools (never shipped in Skyline images)

| Tool | Purpose | Licence | How it runs |
|---|---|---|---|
| gitleaks | Secret scanning (also a pre-commit hook) | MIT | Pinned container / SHA-pinned hook |
| semgrep CE | SAST with p/owasp-top-ten, p/python, p/typescript | Engine LGPL-2.1; rules under the Semgrep Rules License | Pinned container, CI only (owner-approved 2026-11-23) |
| CodeQL | SAST | GitHub-hosted, free for public repos | `github/codeql-action`, SHA-pinned |
| pip-audit | Python vulnerability audit | Apache-2.0 | `uvx`, pinned version |
| Trivy | Image and config scanning | Apache-2.0 | Pinned release binary verified by checksum (not `trivy-action`) |
| Syft | SBOM | Apache-2.0 | Pinned release binary verified by checksum |
| OpenSSF Scorecard | Supply-chain posture | Apache-2.0 | `ossf/scorecard-action`, SHA-pinned |
| pre-commit, pre-commit-hooks | Local hygiene hooks | MIT | Developer machine |

## Licence exceptions

None.
