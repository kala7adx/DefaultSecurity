# 0002. Technology stack and versions

- Status: Proposed
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
`CLAUDE.md` fixes the broad stack: Python/FastAPI/SQLAlchemy/Alembic, Postgres, Next.js, uv and
pnpm. It leaves versions and a few library choices open. The licence policy (ADR-0010) excludes
copyleft dependencies. The owner develops on native Windows 11 (`D:\CloudSecApp`) and deploys to
Linux containers.

## Decision
- **Python 3.13** (`requires-python = ">=3.12"`) via a uv-managed interpreter and
  `.python-version`. 3.13 has a long security-support window and broad wheel coverage.
- **FastAPI + Pydantic v2 + pydantic-settings**, served by **uvicorn**.
- **SQLAlchemy 2 (async)** with the **asyncpg** driver (Apache-2.0). We deliberately avoid
  psycopg 3, which is LGPL-3.0. Alembic runs migrations through the async engine (`run_sync`).
- **PostgreSQL 17** (support for `>=16`). It is available on RDS, Azure Flexible Server and
  Cloud SQL.
- **structlog** for JSON logs, **argon2-cffi** for password hashing, **cryptography** for AES-GCM
  and key handling, **PyYAML** (`safe_load` only), and **httpx** for outbound HTTP (later phases).
- Tests: **pytest**, pytest-asyncio and pytest-cov, with **testcontainers** (Apache-2.0) for a
  real Postgres. RLS can't be tested on SQLite. moto and recorded fixtures for providers in later
  phases.
- Frontend: **Next.js (App Router, `output: "standalone"`)**, TypeScript `strict`, Tailwind,
  shadcn/ui (copied MIT source), TanStack Query and Table, zod for response validation, vitest +
  Testing Library, Playwright for end-to-end tests. Node **LTS 26** locally and in images; pnpm
  pinned with the `packageManager` field.
- Monorepo:
  - Python: a uv workspace (`packages/*`, `apps/api`, `apps/worker`) with src layout. Import
    names are `skyline_core`, `skyline_connectors`, `skyline_checks`, `skyline_frameworks`,
    `skyline_api` and `skyline_worker`.
  - Web: a pnpm workspace with `apps/web`.
- Repository hygiene on Windows: `.gitattributes` enforces `eol=lf`, because `core.autocrlf=true`
  would otherwise put CRLF into shell scripts, Dockerfiles and YAML shipped into Linux containers.

## Consequences
- One Python codebase for the API and worker. Typing is strict and checked by mypy.
- asyncpg means no psycopg-specific features. Alembic and SQLAlchemy support asyncpg fully.
- Python 3.14 features such as `uuid.uuid7` aren't used. IDs are UUIDv4.
- Native Windows means Claude Code can't sandbox commands. The `.claude/settings.json`
  permission lists are the guardrail.

## Alternatives considered
- psycopg 3: excellent, but LGPL-3.0 conflicts with the licence policy.
- Python 3.12 baseline: viable, but it's older. 3.14: very new for some native wheels.
- Postgres 18: newest, but managed-service availability varies.
- Vite SPA instead of Next.js: a simpler CSP, but `CLAUDE.md` fixes Next.js. Revisit only via ADR.

## References
- asyncpg licence: https://github.com/MagicStack/asyncpg/blob/master/LICENSE
- psycopg licence: https://github.com/psycopg/psycopg/blob/master/LICENSE.txt
- uv workspaces: https://docs.astral.sh/uv/concepts/projects/workspaces/
