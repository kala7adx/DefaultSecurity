# Architecture Decision Records

The format and process are in [0001](0001-record-architecture-decisions.md). Statuses:
`Proposed` → `Accepted` → `Deprecated` / `Superseded by NNNN`.

| # | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-technology-stack.md) | Technology stack and versions (Python 3.13, asyncpg, Postgres 17, Next.js) | Accepted |
| [0003](0003-postgres-backed-job-queue.md) | Postgres-backed job queue behind an interface | Accepted |
| [0004](0004-asset-graph-in-postgres.md) | Asset graph in Postgres (nodes/edges) | Accepted |
| [0005](0005-read-only-enforcement.md) | Layered read-only enforcement for connectors | Accepted |
| [0006](0006-secrets-envelope-encryption-keyprovider.md) | Secrets: envelope encryption behind a KeyProvider | Accepted |
| [0007](0007-tenancy-and-row-level-security.md) | Tenancy: shared schema with Postgres RLS | Accepted |
| [0008](0008-web-sessions-opaque-tokens-samesite-lax.md) | Web sessions: opaque tokens, SameSite=Lax + CSRF | Accepted |
| [0009](0009-check-engine-and-framework-mappings.md) | Check engine and framework mappings | Accepted |
| [0010](0010-licence-and-supply-chain-policy.md) | Licence and supply-chain policy | Accepted |
| [0011](0011-customer-onboarding-flow.md) | Customer onboarding: Launch Stack, auto-registration, StackSets | Accepted |
| [0012](0012-skyline-on-aws-reference-deployment.md) | Skyline on AWS: reference deployment | Accepted |
