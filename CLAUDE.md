# CLAUDE.md — Project rules for Claude Code

> Codename: **Skyline** (placeholder — rename later with a find/replace).
> Skyline is an agentless cloud & SaaS security posture platform (CSPM + SSPM, growing toward CNAPP),
> in the same space as Wiz and Orca Security. Full product brief: `docs/PRODUCT_BRIEF.md`.
> Read that brief before starting any new phase.

## What we are building (one paragraph)
A self-hostable, container-based platform that connects **read-only** to cloud accounts (AWS first,
then Azure and GCP) and SaaS tenants (Microsoft 365 / Entra ID / Exchange Online, Google Workspace),
builds a normalised asset inventory and relationship graph, evaluates policy checks against it,
and produces prioritised findings mapped to compliance frameworks (CIS, ISO 27001:2022,
Cyber Essentials, NIST CSF 2.0). It must deploy to any cloud (Docker Compose for a single VM,
Helm for any Kubernetes) and be designed multi-tenant from day one so it can later run as SaaS.

## Project facts
- Personal, open-source project. Licence: Apache-2.0. Repo: `kala7adx/DefaultSecurity`.
- Developed on Windows 11 at `D:\CloudSecApp`. Owner hosts it on AWS; Azure/GCP hosting must also work.

## Tech stack (change only via an ADR in `docs/adr/`)
- Backend: Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2 (async), Alembic. Package manager: `uv`.
- Workers: same Python codebase, job queue behind an interface (start Postgres-backed; Redis optional later).
- Database: PostgreSQL 16+ (JSONB for raw resource config; nodes/edges tables for the asset graph).
- Frontend: Next.js (App Router) + TypeScript + Tailwind + shadcn/ui. Package manager: `pnpm`.
- Lint/format/type: ruff, mypy (strict for `packages/`), eslint, prettier, tsc.
- Tests: pytest (+ moto for AWS, recorded HTTP fixtures for Graph/Google APIs), vitest/playwright for web.
- Packaging: Docker images (non-root, distroless or slim), Docker Compose, Helm chart.
- IaC: Terraform for hosting and for customer onboarding (IAM roles / app registrations).

## Repository layout (target)
```
apps/api/            FastAPI service (REST, auth, tenancy)
apps/worker/         scan scheduler + job runner
apps/web/            Next.js UI
packages/core/       domain models, DB, tenancy, crypto/secrets, audit log
packages/connectors/ one sub-package per provider (aws, azure, gcp, m365, google_workspace, fake)
packages/checks/     check engine + check definitions (YAML metadata + Python evaluators)
packages/frameworks/ compliance framework catalogues and check->control mappings
deploy/compose/      docker-compose for local + single-VM deploy
deploy/helm/         Helm chart
deploy/terraform/    hosting modules (aws/azure/gcp) and onboarding/ (customer-side roles)
docs/                PRODUCT_BRIEF, ARCHITECTURE, THREAT_MODEL, ROADMAP, adr/
```

## Non-negotiable security rules (this product holds the keys to customers' clouds)
1. **Read-only, always.** Connectors may only call read APIs (AWS: `Describe*`, `List*`, `Get*`;
   Graph/Google: GET). Each connector declares an allowlist of the API calls it makes, and a test
   fails the build if a connector calls anything outside it. No remediation actions in the codebase
   unless an ADR explicitly introduces them later.
2. **No long-lived cloud keys.** AWS: cross-account `sts:AssumeRole` with a per-tenant `ExternalId`.
   Azure/Entra: app registration with certificate credential or workload identity federation.
   GCP: workload identity federation or a service account (key only as a last resort, encrypted).
   Google Workspace: service account with domain-wide delegation limited to `*.readonly` scopes.
3. **Secrets are encrypted at rest** with envelope encryption behind a `KeyProvider` interface
   (local dev key, AWS KMS, Azure Key Vault, GCP KMS). Never store secrets in plain DB columns.
4. **Never log secrets, tokens, or raw credentials.** Use the shared redaction logger.
   Treat collected raw config as sensitive: redact known secret-bearing fields
   (e.g. EC2 user data, Lambda env vars, container env) before storing — keep a hash, not the value.
5. **Tenant isolation**: every tenant-owned table has `tenant_id`; enforce with Postgres Row-Level
   Security plus application-level scoping. Tests must prove cross-tenant reads fail.
6. **Every privileged action is audit-logged** (connector added, check muted, exception approved).
7. Dependencies pinned via lockfiles; CI runs gitleaks, pip-audit, pnpm audit, semgrep/bandit,
   and Trivy on images.
8. **Do not copy proprietary code, docs, rule text or UI from Wiz, Orca or any vendor.**
   Open-source code may be used only under a compatible licence; record it in `THIRD_PARTY.md`.
   Flag any AGPL/GPL/BSL/SSPL dependency to the user before adding it.

## Secure coding & code hygiene (full standard: `docs/SECURE_CODING.md` — read it before writing code)
- Target OWASP ASVS Level 2; review against OWASP Top 10 / API Top 10.
- Validate all input with Pydantic (`extra="forbid"`); no string-built SQL; no `eval`/`exec`/`pickle`/
  `yaml.load`; no `shell=True`; every HTTP call has a timeout and TLS verification on;
  user-supplied URLs go through the SSRF guard.
- Deny-by-default authz on every route; tenant scoping + RLS with IDOR tests.
- Full type hints, `mypy --strict` on `packages/`, TS `strict`; ruff with security rules (S) on;
  zero warnings; coverage ≥ 85% on `packages/`; negative tests for security-relevant code.
- GitHub Actions pinned to commit SHAs with minimal `permissions:`; CodeQL, semgrep, gitleaks,
  pip-audit, Trivy and OpenSSF Scorecard in CI.
- Run the `security-reviewer` agent before committing anything touching connectors, auth, tenancy,
  crypto, IaC or CI, and fix its findings. Meet the Definition of Done in `docs/SECURE_CODING.md`.

## How to work in this repo
- Plan before building: for any phase or non-trivial feature, write/refresh the plan first and wait
  for my approval. Record significant decisions as ADRs (`docs/adr/NNNN-title.md`).
- Work in small vertical slices that run end-to-end; keep `main` green.
- Write tests with the code. A check is not "done" without a passing and a failing fixture.
- Conventional Commits (`feat:`, `fix:`, `chore:` …). Commit after each green milestone.
- **Never `git push`, run `terraform apply`, or call real cloud/SaaS APIs without asking me first.**
- Never read or print `.env`, credential files, or `~/.aws`, `~/.azure`, `~/.config/gcloud`.
- When a vendor API detail (permission name, scope, endpoint, benchmark version) matters,
  verify it against current official docs rather than relying on memory, and cite the doc URL
  in the code comment or check metadata.
- Keep this file short. Put detail in `docs/`. Update `docs/ROADMAP.md` status as phases complete.

## Common commands (keep updated as the repo grows)
- `docker compose -f deploy/compose/docker-compose.yml up --build -d --wait` — run everything
  locally (README: reading the bootstrap password); `... down -v` resets it
- `uv run python deploy/compose/smoke_test.py` — end-to-end check on a throwaway stack
- `uv run pytest` — backend tests (Docker needed; coverage gates in CI)
- `uv run ruff check . && uv run mypy && uv run mypy packages` — lint + types
- `pnpm --dir apps/web lint && pnpm --dir apps/web typecheck && pnpm --dir apps/web test` — frontend
