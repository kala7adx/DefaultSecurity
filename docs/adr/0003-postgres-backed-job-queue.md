# 0003. Postgres-backed job queue behind an interface

- Status: Proposed
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Scans, evaluations and onboarding verifications run asynchronously in workers. `CLAUDE.md`
says to start Postgres-backed (Redis optional later) behind an interface. Requirements:
- at-least-once delivery
- retries with backoff
- recovery when a worker dies mid-job
- one active scan per integration
- tenant context set per job
- payloads that can't execute code

## Decision
- Define a `JobQueue` protocol in `skyline_core`: `enqueue`, `claim`, `heartbeat`, `complete`,
  `fail`.
- Implement it on a `jobs` table:
  - Claim with `UPDATE jobs SET status='running', locked_by=:w, lease_expires_at=now()+:lease
    WHERE id = (SELECT id FROM jobs WHERE status='queued' AND run_at <= now() ORDER BY run_at
    FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`, written as SQLAlchemy expressions.
  - Heartbeats extend the lease. A reaper re-queues expired leases.
  - Failures retry with exponential backoff and full jitter up to `max_attempts`, then become
    `dead`.
  - Payloads are JSON holding **IDs only**, validated by a Pydantic model per job `kind`. No
    pickling, and no callables stored by name.
  - A partial unique index enforces one active scan per integration.
- RLS on `jobs`:
  - `skyline_api` may only INSERT rows for the current tenant (`WITH CHECK`).
  - `skyline_worker` has a role-specific policy so it can claim across tenants, then sets
    `app.tenant_id` from the job row before touching any tenant data.
- Scheduler: runs in the worker, leader-elected with `pg_try_advisory_lock`. It reads due
  integrations through the `SECURITY DEFINER` function `skyline_due_integrations()`, which
  returns IDs only.

## Consequences
- No extra infrastructure, which suits Compose and single-VM deployments. Job, scan and finding
  writes can share a transaction.
- Throughput is limited by Postgres, which is ample for posture scanning. If it ever isn't, SQS
  or Redis can replace the backend behind the interface.
- We own about 300 lines of queue code with focused tests: concurrency, lease expiry, retry,
  dedupe.

## Alternatives considered
- procrastinate (MIT): mature. It brings its own schema and migrations outside Alembic, and less
  control over tenant-context semantics.
- pgqueuer (MIT): similar trade-off.
- Celery + Redis: another service, and pickle-adjacent defaults that need hardening.

## References
- PostgreSQL `SELECT … FOR UPDATE SKIP LOCKED`: https://www.postgresql.org/docs/current/sql-select.html#SQL-FOR-UPDATE-SHARE
- Advisory locks: https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS
