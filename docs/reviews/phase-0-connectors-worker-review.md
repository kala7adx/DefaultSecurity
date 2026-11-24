# Phase 0 connectors + worker: security review findings

Reviewer: `security-reviewer` agent, 2026-11-23, on commits f8ef4cb (packages/connectors) and
a394d4b (apps/worker). These were committed before this review ran (a process slip), so the
fixes land as a follow-up `fix:` commit. **Status: round 1 and round 2 (below) fixed; the
round-2 fixes went back to the reviewer for a final check.** Tests: `packages/connectors/tests/*`, `apps/worker/tests/test_review_fixes.py`,
`apps/worker/tests/test_migrate.py`.

| Finding | Fix | Test |
|---|---|---|
| **H1** rejected records looked deleted | Runner keeps `rejected_ids`; a rejected record without a usable ID sets `unsafe_to_delete`. Store never deletes rejected IDs (or their edges), and an unsafe scope deletes nothing. Lifecycle evaluates only assets seen in this scan, so stale ones keep their findings. | `test_rejected_records_keep_their_assets_and_open_findings`, `test_scope_with_an_unusable_record_id_deletes_nothing` |
| **M1** unstorable JSON | `strict_json`: JSON types only, finite floats, no NUL, no lone surrogates, text keys. | `test_unstorable_json_is_rejected_and_kept_as_not_deleted` |
| **M2** gateway was the only runtime check | The transport is built with the validated allowlist and re-checks every call. Recording-transport fixture test. AST rules are an import **allowlist**, ban `*.transport` imports outside the registry, and ban reflection built-ins, `importlib` and private attributes of other objects. | `test_transport_enforces_its_own_allowlist`, `test_calls_seen_by_the_transport_are_all_allowlisted`, AST tests |
| **M3** data-plane "reads" allowed | `DENIED_SDK_OPERATIONS` (secrets, object/record data, console output, credential minting); HTTP content paths and `..` denied. | one negative test per entry |
| **M4** verify races | Verdicts are conditional on an `IntegrationSnapshot` (status, config, credential, not deleted). The onboarding scan is enqueued in a savepoint, so an active scan doesn't roll back the reconnect. Transient errors retry; dead verify jobs go to `access_lost` (unless a newer verify is queued). The scan's access_lost is conditional too. | `test_verdict_is_dropped_if_the_config_changed_during_the_check`, `test_transient_errors_retry_and_only_then_give_up`, `test_reverify_with_a_scan_already_active_still_reconnects` |
| **M5** leases | One worker ID per loop. The heartbeat retries on DB errors and cancels the handler when the lease is lost. Handlers lock and check job ownership (`queue.owns`, `FOR UPDATE`) in their final transaction. `_finish` closes only active runs; queue `_finish`/`fail` require `running`. | `test_a_scan_whose_lease_moved_commits_nothing`, `test_heartbeat_survives_errors_and_cancels_the_handler_when_the_lease_is_lost` |
| **M6** memory / DoS | Byte budgets per scope (64 MB) and per scan (256 MB), scope count cap, record cap. The worker's idle-in-transaction timeout is configurable (default 300 s). **Deferred:** persisting per scope (results are still stored in one final transaction); revisit with the real AWS connector in Phase 1. | `test_scope_byte_cap_fails_the_scope`, `test_scan_byte_budget_is_shared_across_scopes` |
| **L1** duplicates | Within and across scopes: the first successful scope owns an ID. | `test_duplicates_*`, `test_failed_scope_does_not_claim_shared_ids` |
| **L2** empty or odd discovery | `validate_scopes`: none, too many, duplicate or malformed IDs fail the scan. | `test_unusable_scope_lists_fail_discovery`, `test_empty_discovery_fails_the_scan` |
| **L3** relationship properties unredacted | Redacted with the integration's rules; size cap. | `test_relationship_properties_are_redacted` |
| **L4** edges from other scopes | Kept only if the source belongs to the scope. | `test_edges_from_another_scopes_assets_are_dropped` |
| **L5** read-only violation was per scope | Any violation fails the whole scan, stores nothing, and writes a `connector.read_only_violation` audit row. Unexpected errors log their type only. | `test_read_only_violation_fails_the_whole_scan_and_is_audited`, `test_unexpected_error_messages_are_not_logged` |
| **L6** scheduler | Per-integration try/except; `next_scan_at` moves on even when a scan is active (no starvation); the connection is invalidated if unlock fails. | `test_scheduler_moves_busy_integrations_on` |
| **L7** reaper | Each dead job is settled on its own; dead verify jobs are handled; a sweeper re-settles recently dead jobs. | `test_sweeper_closes_runs_whose_job_died_unsettled` |
| **L8** bootstrap / migrate | Bootstrap runs in one transaction; migrate holds an advisory lock (polled, so `statement_timeout` doesn't cut the wait). | `test_bootstrap_is_all_or_nothing`, `test_migrate_lock_serialises_runs` |
| **L9** catalogue integrity | The content hash includes the evaluator source; the worker refuses to start on drift. | `test_content_hashes_are_stable_and_distinct`, `test_catalogue_drift_is_detected` |
| **L10** evaluate job | Runs only for the latest stored scan; skips whole-run failures. | `test_evaluate_only_runs_for_the_latest_stored_scan` |
| **L11** demo provider | `fake` is `demo_only`: it needs `env=development` or `SKYLINE_DEMO_PROVIDER_ENABLED=true`, checked in the worker and in the API. | `test_demo_provider_is_refused_unless_enabled` |

## Round 2 (re-review, 2026-11-24)

The re-review confirmed H1, M1, M4, M5, L2, L3 and L8 to L11 as fixed, and raised:

| Finding | Fix | Test |
|---|---|---|
| **M-1** the final scan transaction ignored changes made during the scan | After `owns()`, the integration row is locked only if it still matches the snapshot. If it doesn't, the run fails ("the integration changed during the scan"), nothing is stored, and `next_scan_at = now()` (not for deleted integrations). Verify's "scan already active" branch also sets `next_scan_at = now()`. A busy integration is retried after at most 15 min. | `test_a_scan_stores_nothing_if_the_integration_changed_meanwhile[delete/reconfigure]` |
| **M-2** violations caught only when unhandled | `ApiNotAllowedError` derives from `ReadOnlyGuardError`, not `ConnectorError`. The gateway records every refusal, including the transport's. Scan and verify check that record after each step. A verify violation is audited, leaves the status alone and isn't retried (`PermanentJobError`). | `test_a_violation_during_discovery_is_audited`, `test_a_swallowed_violation_still_stops_the_scan`, `test_a_violation_during_verify_is_audited_and_not_retried`, `test_violations_are_seen_even_when_a_connector_swallows_them` |
| **M-3** AST rules bypassable | `find_violations()` covers allowlisted import names, registry-only internals, banned reflection names, dunders, foreign private attributes and `object`/`type`/`asyncio` attributes. It is tested against a corpus of every reported bypass. ADR-0005 records that this is a tripwire. | `test_the_rules_catch_each_known_bypass`, `test_connector_package_follows_the_static_rules` |
| **M-4** budgets didn't bound memory | The budgets charge whole assets (tags, names, IDs), edges and rejected IDs. Duplicates and rejects count toward the record caps. New `max_records_per_scan` (500k). The ROADMAP Phase 1 entry gate requires per-scope persistence and evaluation off the event loop. | `test_tags_and_edges_count_against_the_byte_budgets`, `test_duplicates_and_rejects_count_towards_the_record_caps` |
| **L-1** deny list incomplete | More credential-minting, secret-returning and content reads added (re-checked per service in Phase 1). | one negative test per entry |
| **L-2** HTTP checks at registration only | Phase 2+ rules for path parameters and query parameters written into ADR-0005. | (design) |
| **L-3** unchecked provider text | `clean_text()` in `safe_reason`, logs and the verify detail. | `test_provider_text_is_cleaned_before_storage` |
| **L-4** scan / evaluate race | Evaluate locks the integration row before choosing "latest", as the scan does. | (lock order) |
| **L-5** scheduler | The lock is acquired inside the error handling (the connection is invalidated if unsure); the per-integration update requires connected and not deleted. | `test_scheduler_moves_busy_integrations_on` |
| **L-6** sweeper coverage | Sweeps DEAD jobs only. A cross-tenant orphan-run sweep and the index are a Phase 1 entry-gate item. | `test_sweeper_closes_runs_whose_job_died_unsettled` |
| **L-7** access_lost without an ownership check | Done inside `fail_scan`'s transaction after `owns()`. | covered by the scan tests |
| Info | The shutdown cancel isn't swallowed (`cancelling()`); IntegrityError handling checks the constraint name; `mypy packages` (tests included) is clean. | |
