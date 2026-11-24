# Phase 0 API slice: security review findings (open)

Reviewer: `security-reviewer` agent, 2026-11-24, on the uncommitted `apps/api` slice.
Verdict: **fix before commit**. Tenant isolation, RBAC and CSRF held up.
**Status: fixed in the working tree (table below); sent back for re-review.**

## High
- **H1 Throttling races.** Login and change-password read the failure count, hash for about
  100 ms, then record the failure in a separate transaction. 40 parallel bad logins against one
  account all returned 401 and none returned 429. Fix: an atomic SECURITY DEFINER
  `begin_login_attempt` (advisory xact lock on the subject, count, insert a pending failure, return
  allowed/retry_after/attempt_id) and `finish_login_attempt(id, succeeded)`. Add a concurrency test
  that expects exactly N 401s and the rest 429.

## Medium
- **M1 Client IP.** `trusted_proxy_hops=0` turns the per-IP bucket into one global lockout behind
  the proxy. Fix: refuse to start in production unless it is set explicitly; group IPv6 by /64;
  put an unknown IP in a fixed bucket instead of skipping the check; document that the API must be
  reachable only from the proxy.
- **M2 Login CPU/DB flood.** Nothing caps concurrent argon2 hashing (default thread pool) and
  each attempt opens 3–4 transactions. Fix: a process-wide semaphore with a non-blocking acquire
  (return 503); reserve the attempt before hashing; set uvicorn `limit_concurrency`.
- **M3 500 responses** have no security headers or `X-Request-ID`, and `correlation_id` is null,
  because the Exception handler runs outside the user middleware and the context is cleared first.
  Fix: catch exceptions in `RequestContextMiddleware`, log with the correlation ID, return a
  generic 500 with the headers. Test a route that raises.
- **M4 Audit gaps.** A wrong current password on change-password isn't audited. A change-password
  429 and failed logins for known users are tenant-less rows. Fix: tenant-scoped
  `auth.password.change_failed` / throttle rows with the actor, plus a tenant-scoped row for
  failed logins on existing users, with the HMAC subject in `details`.

## Low
- **L1** NUL bytes in string input cause an unauthenticated 500 (`CharacterNotInRepertoireError`).
  Use a shared string type that rejects NUL and C0 characters in the schemas and every `Query`, and
  map `DataError` to 422.
- **L2** Safe methods write: the session touch (allowed, document it) and `authz.denied` audits
  on GET (a cross-site link under Lax can make a viewer write them). Don't audit denials on safe
  methods. Replace the name-based test with one that calls every GET route and checks that
  nothing but `sessions.last_seen_at` changed.
- **L3** No pre-session login CSRF token, although ADR-0008 says there is one. The Origin check
  plus JSON-only bodies block login CSRF today. Implement the token or amend the ADR.
- **L4** Targeted lockout: 10 bad passwords every 5 minutes keep an account locked, change-password
  included. Use a known-device cookie that skips the account bucket, or progressive delays.
- **L5** Unlimited verify jobs and scans. Add a partial unique index on active verify jobs and a
  per-integration scan cooldown.
- **L6** Deleting an integration leaves its assets readable and its credential stored. Filter
  assets on live integrations and purge the secret.
- **L7** Some statements look rows up by ID without an explicit tenant predicate (RLS covers
  them). Add `tenant_id ==` to each (integrations, exceptions, scans, auth).
- **L8** Thin audit details: `integration.updated` (field names only), `exception.created` (no
  targets). Record non-secret before/after values and target IDs.
- **L9** A client `X-Request-ID` becomes the audit `correlation_id`. Generate it on the server and
  keep the client's ID separately.
- **L10** `_INVALID` is one shared exception instance, so tracebacks chain across requests. Use a
  factory.
- **L11** Expensive queries: offset up to 100k with `count(*)`, leading-wildcard ILIKE with no
  trigram index, unauthenticated `/readyz` hits the DB. Lower the offset cap, add a `pg_trgm`
  index, keep `/readyz` off public routes.
- **L12** HSTS defaults to off in production. Default it on, or refuse to start without it.
- **L13** With the local KEK the API holds a provider that can also unwrap, so encrypt-only is a
  database rule, not a cryptographic one. Document the residual risk (KMS splits it).
- **Nits:** an over-limit streamed body returns 400 instead of 413; `validate_origin` keeps
  default ports (fails closed).

## Worker issue the API review spotted
PATCHing a connected integration's config while a scan is active can leave it stuck in
`verifying`: the onboarding-scan insert in `verify._record` hits `uq_jobs_one_active_scan` and
rolls back the status update. Covered by worker M4 (enqueue in `begin_nested()`).

## Fixes

| Finding | Fix | Test |
|---|---|---|
| H1 | `skyline.begin_login_attempt` locks the account and IP subjects, counts, and reserves the attempt as a failure in one step. `finish_login_attempt` marks it succeeded or cancels it. `record_login_attempt` was removed, and `recent_login_failures` is now internal only. | `test_account_throttle_holds_under_parallel_requests` (exactly 10 × 401 out of 30), `test_ip_throttle_holds_under_parallel_requests`, `test_login_attempt_functions` |
| M1 | `trusted_proxy_hops` must be set explicitly in production. IPv6 is bucketed by /64, IPv4-mapped addresses count as IPv4, and an unknown IP gets a fixed bucket. Compose sets 1 hop. | `test_ip_buckets`, `test_production_needs_explicit_proxy_hops_and_defaults_hsts_on` |
| M2 | Argon2 runs in `hash_slots` (default 8, a non-blocking acquire that returns 503 when full). The attempt is reserved before hashing. uvicorn `limit_concurrency`. | `test_login_sheds_load_when_hashing_is_saturated` |
| M3 | `RequestContextMiddleware` catches unhandled errors while the correlation ID is still bound. The security headers are now the outermost middleware. | `test_unhandled_errors_keep_headers_and_correlation_id` |
| M4 | Tenant-scoped `auth.login.failed` rows for known accounts, `auth.password.change_failed` and `auth.password.change_throttled`, each with an HMAC subject reference. | `test_failed_logins_on_known_accounts_reach_the_tenant_audit_log`, `test_wrong_current_password_is_audited_in_the_tenant` |
| L1 | A shared `SafeText` type (no NUL or C0 controls) on every request string and query parameter. | `test_control_characters_are_rejected_not_500` |
| L2 | Denied reads are logged, not audited. The session touch is the documented exception. | `test_denied_reads_are_not_written_to_the_audit_log` |
| L3 | ADR-0008 amended: login CSRF is covered by Origin, Sec-Fetch-Site and JSON-only bodies. | existing Origin and JSON tests |
| L4 | Accepted risk R9 (Cyber Essentials needs the lockout); a known-device bypass is planned for Phase 1. | — |
| L5 | `uq_jobs_one_queued_verify` and an idempotent `_enqueue_verify`. Scan cooldown: Phase 1 (real AWS). | `test_repeated_verify_requests_queue_one_job` |
| L6 | Assets of deleted integrations are hidden. Deleting an integration removes its sealed credential (a RESTRICTIVE DELETE policy limits this to credentials). | `test_delete_integration_hides_its_findings_and_assets`, `test_deleting_an_integration_removes_its_credential` |
| L7 | Explicit tenant predicates added everywhere listed. | existing IDOR tests |
| L8 | `integration.updated` records non-secret before/after values; `exception.created` records its targets. | `test_integration_updates_are_audited_with_before_and_after` |
| L9 | The correlation ID is always generated by the server; the client's ID is logged as `client_request_id`. | `test_security_headers_and_correlation_ids` |
| L10 | `_invalid_credentials()` creates a fresh error per raise. | — |
| L11 | Offset capped at 10,000. `/readyz` stays off the web proxy (only `/api/v1/*` is proxied). Trigram index: Phase 5 (search). | — |
| L12 | HSTS defaults on in production. | `test_production_needs_explicit_proxy_hops_and_defaults_hsts_on` |
| L13 | Residual risk R8 recorded in ADR-0006 and THREAT_MODEL. | — |
| Nits | A streamed over-limit body now returns 413; default ports are normalised in `validate_origin`. | `test_oversized_bodies_are_rejected`, `test_default_ports_are_the_same_origin` |

## Round 2 (re-review, 2026-11-24)

| Finding | Fix | Test |
|---|---|---|
| N1 (High) one IP could make everyone's login return 503 | The reservation comes first, with `pg_try_advisory_xact_lock` (a busy subject gets 429 at once; nobody waits holding a connection). A hashing slot is taken only around argon2, capped per IP bucket (`max_concurrent_hashes_per_ip`, default 2). A busy slot cancels the reservation. | `test_one_ip_cannot_take_every_hashing_slot`, the parallel throttle tests |
| N2 (Medium) Next.js doesn't append X-Forwarded-For | Hops count only proxies that *append* (Next.js counts as 0). Compose uses 0; production behind an ALB uses 1. A header shorter than the hop count puts the request in the "unknown" bucket, never the proxy's. Message and comments corrected. | `test_short_x_forwarded_for_falls_back_to_the_unknown_bucket` |
| N3 (Medium) login timing revealed which emails exist | Failure audit rows are written in a BackgroundTask after the response. Every path does the same lookup and no extra transaction before responding. | existing audit tests (rows still written) |
| N4 (Low) READ COMMITTED dependency | The engine pins READ COMMITTED; `begin_login_attempt` refuses any other isolation level. | `test_login_attempt_functions` |
| N5 (Low) `finish_login_attempt` accepts any IDs | Accepted: not reachable over HTTP, and the API role already receives password hashes, so a reservation token adds no real boundary. Revisit if the API's DB role is ever split. | — |
| N6 (Low) path parameter | `framework_id` is `SafeText`. | — |
| N7 (Low) purge caveats | The comment no longer claims crypto-shredding (WAL and backups keep copies until they age out). The guard trigger lets the API only clear `credential_secret_id`. | `test_the_api_can_only_clear_an_integration_credential` |
| N8 (Low) throttled known accounts invisible to the tenant | A tenant row is written too (after the response). | — |
| N9 (Nit) oversized audit details | Truncation keeps the top-level keys and a SHA-256 of the full details. | `test_audit_entries_are_redacted_and_tenant_scoped` |
