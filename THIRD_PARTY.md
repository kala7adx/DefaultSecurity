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
| pip-audit | Vulnerability audit of the locked dependencies | Apache-2.0 |
| pip-licenses | Licence gate (with `scripts/check_licences.py`) | MIT |
| pytest, pytest-asyncio | Tests | MIT, Apache-2.0 |
| ruff | Lint (incl. bandit rules) and format | MIT |
| testcontainers | Real PostgreSQL in tests | Apache-2.0 |
| types-pyyaml | Type stubs | Apache-2.0 |

Notable transitive licences: `certifi` and `pathspec` are MPL-2.0 (allowed);
`typing-extensions` and `greenlet` include PSF-2.0 (owner-approved, ADR-0010);
`cffi` is MIT-0 (owner-approved).

## Web dependencies (direct)

| Package | Purpose | Licence |
|---|---|---|
| next, react, react-dom | Web UI (App Router, standalone server) | MIT |
| @tanstack/react-query | Data fetching and caching | MIT |
| @radix-ui/react-dialog | Accessible finding drawer | MIT |
| clsx, tailwind-merge | Class names | MIT |
| tailwindcss, @tailwindcss/postcss | Styling | MIT |
| typescript (6.0), eslint (9), eslint-config-next, prettier | Types, lint, format (dev) | Apache-2.0, MIT |
| vitest, jsdom, @testing-library/*, @vitejs/plugin-react | Unit tests (dev) | MIT |
| @playwright/test | Browser end-to-end tests (dev) | Apache-2.0 |

`sharp` (an optional Next.js dependency whose libvips binaries are LGPL-3.0) is excluded via
`ignoredOptionalDependencies`; image optimisation is off (`images.unoptimized`).
`caniuse-lite` data is CC-BY-4.0 (owner-approved data licence). TypeScript is pinned to 6.0
and ESLint to 9 because typescript-eslint and several Next.js ESLint plugins don't support
TypeScript 7 / ESLint 10 yet.

## CI-only tools (never shipped in Skyline images)

| Tool | Purpose | Licence | How it runs |
|---|---|---|---|
| gitleaks | Secret scanning (also a pre-commit hook) | MIT | Pinned container / SHA-pinned hook |
| semgrep CE | SAST with p/owasp-top-ten, p/python, p/typescript | Engine LGPL-2.1; rules under the Semgrep Rules License | Pinned container, CI only (owner-approved 2026-11-23) |
| CodeQL | SAST | GitHub-hosted, free for public repos | `github/codeql-action`, SHA-pinned |
| Trivy | Image and config scanning, CycloneDX SBOMs | Apache-2.0 | Container pinned by digest (not `trivy-action`) |
| OpenSSF Scorecard | Supply-chain posture | Apache-2.0 | `ossf/scorecard-action`, SHA-pinned |
| pre-commit, pre-commit-hooks | Local hygiene hooks | MIT | Developer machine |

## Licence exceptions

- `certifi` and `pathspec` are MPL-2.0 (weak, file-level copyleft), used unmodified as
  transitive dependencies. Allowed by the CI licence gate; flagged to the owner 2026-11-24.
