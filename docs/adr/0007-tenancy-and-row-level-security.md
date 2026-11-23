# 0007. Tenancy: shared schema with Postgres Row-Level Security

- Status: Accepted (owner approval 2026-11-23)
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
`CLAUDE.md` rule 5: every tenant-owned table has `tenant_id`, isolation is enforced with Postgres
RLS **plus** application scoping, and tests prove cross-tenant reads fail. The platform is
self-hosted single-tenant first, but must become multi-tenant SaaS (Phase 9) without a rewrite,
including MSP parent/child tenants (Phase 22).

## Decision
- **Shared schema, `tenant_id uuid NOT NULL`** on every tenant-owned table. Each such table has
  `ENABLE` + `FORCE ROW LEVEL SECURITY` and a policy using
  `tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid` for both `USING` and
  `WITH CHECK`. If the tenant isn't set the policy fails closed and returns zero rows.
- The tenant is set **per transaction** with `SELECT set_config('app.tenant_id', :tid, true)` as
  a bound parameter, in one session-scoped helper. It never uses `SET` on a pooled connection
  without `LOCAL` semantics.
- **Database roles** (none with `BYPASSRLS`, app roles don't own tables):
  - `skyline_owner` runs migrations.
  - `skyline_api` serves the API. It has INSERT-only access to secret ciphertext.
  - `skyline_worker` runs jobs. It has a role-specific `jobs` claim policy.
- **Pre-tenant operations** go only through `SECURITY DEFINER` functions owned by
  `skyline_owner`, each with `SET search_path = pg_catalog, skyline`. Each returns the minimum
  columns:
  - `skyline_auth_user(email_norm)`
  - `skyline_auth_session(token_hash)`
  - `skyline_consume_onboarding_token(token_hash)`
  - `skyline_due_integrations()`
  - login-throttle helpers
- **Identity model:** a global `users` table plus tenant-scoped `memberships(role)`. A session
  carries the active `tenant_id`. Bootstrap creates a `default` tenant.
- **Application scoping:** every repository function takes a `TenantContext` and filters by
  `tenant_id` explicitly. RLS is the backstop.
- **Global catalogue tables** (`checks`, `frameworks`, `controls`, `check_control_map`) are
  read-only to the app roles.
- **Mandatory tests:**
  - cross-tenant SELECT, UPDATE, DELETE and INSERT fail
  - an unset tenant returns 0 rows
  - each `SECURITY DEFINER` function returns only its documented columns
  - an IDOR test for every resource endpoint

## Consequences
- One database and one migration path. Isolation holds even if a query forgets its filter.
- Superusers and table owners bypass RLS unless `FORCE` is set, and superuser connections are
  never used by the apps. Managed-DB admin access is an operator concern, covered in the threat
  model.
- Cross-tenant platform features (SaaS operator views) need explicit, audited functions later.

## Alternatives considered
- Schema per tenant: migration fan-out, connection-pool pressure, harder analytics.
- Database per tenant: strongest isolation, heaviest operations. A future option for regulated
  SaaS customers, behind the same repository layer.

## References
- Row security policies: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- `set_config`: https://www.postgresql.org/docs/current/functions-admin.html#FUNCTIONS-ADMIN-SET
- `SECURITY DEFINER` safety: https://www.postgresql.org/docs/current/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY
