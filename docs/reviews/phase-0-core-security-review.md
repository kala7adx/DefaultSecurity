# Phase 0 core slice: security review findings (fixed)

Reviewer: `security-reviewer` agent, 2026-11-23. Scope: uncommitted `packages/core` slice
(migrations 0001/0002, roles, crypto, redaction, queue, audit). **Verdict: fix before commit.**
No critical findings. All items below were fixed on 2026-11-23 before the slice was committed;
each has a regression test in `packages/core/tests/`.

## High
- **H1 `users` has no RLS.** The API role can SELECT emails and UPDATE `password_hash` of every
  user; `user_memberships(uid)` and `revoke_user_sessions(uid)` accept any user id.
  Plan: ENABLE+FORCE RLS on `users` (membership in `current_tenant_id()`), definer and owner
  policies; revoke API UPDATE on `password_hash`; add definer `change_password(token_hash,
  new_hash)` that only changes the session's own user and revokes their other sessions; fold
  memberships into `auth_lookup_user(email)` (active users only) and drop `user_memberships` and
  `revoke_user_sessions` from the API; RLS on `tenants` (`id = current_tenant_id()`) so `/auth/me`
  can read its tenant name. IDOR tests on `users`.

## Medium
- **M1** `auth_lookup_user` + global email SELECT lets SQLi dump hashes. Fixed by H1; return
  hashes for `status='active'` only.
- **M2** API can plant a tenant's redaction HMAC key. Plan: RESTRICTIVE insert policy
  (`purpose = 'integration_credential'` for `skyline_api`), column-level INSERT excluding
  `created_at`, reference the key by `tenants.redaction_key_secret_id` instead of "newest".
- **M3** Redaction misses `DB_PASSWORD=`, `client_secret=`, quoted JSON keys, Basic auth, vendor
  token prefixes (`ghp_`, `xox?-`, `sk_live_`, `AIza`, `AccountKey=`, SAS `sig=`), and raw-config
  keys like `Environment`, `ClientSecret`, `connectionStrings`. Plan: normalise keys (lower-case,
  strip `_`/`-`, substring match), `(?<![A-Za-z0-9])` prefixes, optional quotes, negative tests.
- **M4** Engines lack `hide_parameters=True`, so bound values (bootstrap passwords, hashes) can
  reach logs and `jobs.last_error`. Plan: set it on every engine; `PostgresJobQueue.fail()`
  redacts its error itself.
- **M5** `resolve_session` returns revoked/expired sessions and ignores user and tenant status;
  `due_integrations` includes suspended tenants. Plan: filter both in SQL; tests.

## Low
- **L1** API INSERT on `jobs` is table-wide; reaper doesn't validate payloads; `integration_id`
  can differ from the payload. Plan: column INSERT `(id, tenant_id, kind, integration_id,
  payload, max_attempts)`, `CHECK (jsonb_typeof(payload) = 'object')`, decode in the reaper,
  derive `integration_id` from the payload.
- **L2** Worker UPDATE on `jobs` limited to status/lease/attempt columns.
- **L3** API UPDATE on `sessions` limited to `(last_seen_at, revoked_at)`.
- **L4** Tenant-less audit rows: allow only `auth.login.failed` / `auth.login.throttled` for app
  roles; platform events from the owner only.
- **L5** `REVOKE ALL ON DATABASE … FROM PUBLIC`, grant CONNECT to app roles; default privileges
  revoking function EXECUTE from PUBLIC for owner and definer; add `pg_temp` last in definer
  `search_path`.
- **L6** Plain-env secret check is case-sensitive; make it case-insensitive.
- **L7** Role passwords reach the server in cleartext. Plan: compute SCRAM-SHA-256 verifiers in
  Python (`secrets-init` writes verifier files for the Postgres init script).
- **L8** Compute the argon2 dummy hash at import/startup (first-request timing oracle).
- **L9** `created_by` / `requested_by` / `approved_by` / `revoked_by` should be composite FKs to
  `memberships(tenant_id, user_id)`.

## Tests to add with the fixes
- `pg_auth_members` (definer → owner) has `inherit_option = false`; api/worker have no memberships.
- Cross-tenant `users` SELECT/UPDATE; `resolve_session` on revoked, expired, suspended sessions.
- API cannot insert a `redaction_hmac_key` or set `created_at` / `status` on `secrets` / `jobs`.

## Resolution summary

| ID | Fix | Test |
|---|---|---|
| H1, M1 | RLS on `users` (members of the current tenant) and `tenants` (current tenant); API has no UPDATE on `password_hash`; `change_password(token_hash, hash)` changes only the session's own user and revokes all their sessions; `auth_lookup_user` returns active users with active memberships only; `user_memberships` and `revoke_user_sessions` removed | `test_users_are_visible_only_within_the_tenant`, `test_api_cannot_change_another_tenants_user`, `test_change_password_*`, `test_auth_lookup_returns_only_active_memberships` |
| M2 | RESTRICTIVE insert policy (API seals `integration_credential` only); column INSERT without `created_at`; `tenants.redaction_key_secret_id` set by the owner | `test_api_cannot_plant_a_redaction_key`, `test_api_cannot_backdate_or_postdate_secrets`, `test_redaction_key_is_referenced_by_the_tenant` |
| M3 | Normalised key matching, quote-tolerant key=value pattern, Basic auth, GitHub/Slack/Stripe/Google token formats | `test_common_secret_layouts_are_masked`, `test_vendor_token_formats_are_masked`, `test_*_keys_are_normalised` |
| M4 | `hide_parameters=True` on every engine; `fail()` redacts | `test_fail_redacts_errors_itself` |
| M5 | `resolve_session` filters revoked, expired, idle, disabled user, suspended tenant; `due_integrations` skips suspended tenants | `test_resolve_session_fails_closed` |
| L1 | Column INSERT on `jobs`; `CHECK (jsonb_typeof(payload) = 'object')`; reaper decodes and dead-letters; `integration_id` derived from the payload | `test_api_cannot_set_job_state_or_schedule`, `test_reaper_dead_letters_undecodable_jobs`, `test_payload_must_be_an_object` |
| L2 | Worker UPDATE on `jobs` limited to state/lease columns | `test_worker_cannot_rewrite_job_identity` |
| L3 | API UPDATE on `sessions` limited to `(last_seen_at, revoked_at)` | `test_api_cannot_extend_or_reassign_sessions` |
| L4 | Tenant-less audit rows: API pre-auth login events only; platform events by the owner; `id`/`at` not insertable | `test_tenantless_audit_rows_cannot_be_forged`, `test_audit_time_and_id_cannot_be_set_by_apps` |
| L5 | Database CONNECT/TEMP revoked from PUBLIC; default EXECUTE revoked for owner and definer; `pg_temp` last in definer `search_path` | `test_database_and_membership_privileges`, `test_definer_functions_are_pinned_and_not_public` |
| L6 | Case-insensitive plain-env secret check | `test_secret_in_plain_env_var_is_rejected` |
| L7 | SCRAM-SHA-256 verifiers computed client-side; the server never sees role passwords | every DB test logs in with the cleartext password, proving the verifier |
| L8 | argon2 dummy hash computed at import | covered by `test_verify_unknown_user_and_garbage_hash` |
| L9 | `created_by`, `requested_by`, `approved_by`, `revoked_by` are composite FKs to `memberships` | `test_models_match_migrations` (schema) |

Also added (beyond the review): a trigger stops the API role from ever setting an integration
to `connected` (ADR-0011), with `test_api_cannot_mark_an_integration_connected`.

## Second round (re-review of the fixes)

| ID | Finding | Fix | Test |
|---|---|---|---|
| N1 | API could read `sessions.token_hash`, which `change_password` trusts | Column SELECT without `token_hash`; the API updates sessions by id; `change_password` also enforces the idle timeout | `test_api_cannot_read_token_hashes`, `test_resolve_session_fails_closed` |
| N2 | Quadratic key=value regex (ReDoS) | Every pattern starts at a literal with bounded repeats; log strings truncated at 8 KB, config strings over 32 KB become markers | `test_redaction_is_linear_time` |
| N3 | Substring matching hid check-relevant config (`HttpTokens`, `PasswordPolicy` …) | Exact normalised key names for raw config (substring matching stays for logs) | `test_check_relevant_fields_survive_raw_config_redaction` |
| N4 | `external_id` client-insertable, not unique | Generated by PostgreSQL (`gen_random_uuid()` ×2, 244 bits), `UNIQUE`, not in the API INSERT grant | `test_external_ids_are_generated_unique_and_not_client_settable` |
| L1 | Sessions/exceptions could be un-revoked; `last_seen_at` pushed forward; any `expires_at` | `sessions_guard` / `exceptions_guard` triggers (revocation one-way, timestamps clamped to now), `CHECK (expires_at <= created_at + 72h)` | `test_sessions_cannot_be_unrevoked_or_kept_alive_into_the_future`, `test_sessions_have_a_maximum_lifetime`, `test_exceptions_cannot_be_unrevoked` |
| L2 | Status trigger was a deny-list by role | Allowlist (`skyline_worker`, `skyline_owner`); a config change by anyone else sends a connected integration back to `verifying`; `search_path` pinned | `test_api_cannot_mark_an_integration_connected`, `test_invalid_config_fails_verification` |
| L3 | Empty `SKYLINE_DB_PASSWORD` accepted | Rejected when present at all | `test_empty_plain_secret_env_var_is_rejected` |
| L4 | Escaped JSON and quoted values with spaces leaked | Quoted, escaped-quoted and bare value alternatives | `test_quoted_and_escaped_values_are_fully_masked` |
| L5 | `tenants.redaction_key_secret_id` had no FK | Composite FK to `secrets(tenant_id, id)`, created after both tables | `test_models_match_migrations` |
| L6 | `jobs.integration_id` could differ from the payload | `CHECK (integration_id::text IS NOT DISTINCT FROM payload->>'integration_id')` | `test_indexed_integration_must_match_the_payload` |

## Third round (final check)

All round-two items confirmed resolved. Two follow-ups, fixed:

| Finding | Fix | Test |
|---|---|---|
| Medium: any ARN containing `:secret:` turned a whole policy string into a marker (false negatives for policy checks) | `(?<![:/])` before the key=value keywords; raw-config strings now have only their secret-shaped spans replaced, by `[REDACTED:<keyed HMAC tag>]` | `test_policies_mentioning_secret_arns_survive`, `test_only_secret_spans_are_masked_in_config_strings` |
| Low: DB session lifetime cap (72 h) looser than the 12 h policy | `CHECK (expires_at <= created_at + interval '12 hours')`; the setting is capped at 12 | `test_sessions_have_a_maximum_lifetime` |

These two fixes were not sent back to the reviewer; the tests above cover them.
