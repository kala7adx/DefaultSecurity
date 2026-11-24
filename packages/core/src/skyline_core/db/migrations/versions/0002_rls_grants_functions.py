"""Row-Level Security, least-privilege grants and SECURITY DEFINER lookups (ADR-0007).

Roles (created outside migrations by the database bootstrap, none with BYPASSRLS):

* ``skyline_owner``   owns the schema and runs migrations and bootstrap only.
* ``skyline_api``     the API. Seals integration credentials but can't read key material,
  can't read password hashes, and can only see users who belong to the current tenant.
* ``skyline_worker``  the worker. Opens secrets; claims jobs of every tenant (worker policy).
* ``skyline_definer`` NOLOGIN. Owns the SECURITY DEFINER functions for the few lookups that
  must happen before a tenant is known (login, session, password change, throttling,
  scheduler). The owner is a member WITH INHERIT FALSE, SET TRUE.

Grants are column-level wherever a role should not control a column (timestamps, status,
ownership). Every statement here is static SQL; nothing is built from input.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-23
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copies: migrations must not import application constants that may change later.
TENANT_TABLES = (
    "memberships",
    "sessions",
    "secrets",
    "integrations",
    "jobs",
    "scan_runs",
    "assets",
    "relationships",
    "findings",
    "finding_events",
    "exceptions",
)
RLS_TABLES = (*TENANT_TABLES, "audit_log", "users", "tenants")

# pg_temp last, as the CREATE FUNCTION docs recommend for SECURITY DEFINER functions.
DEFINER = "SECURITY DEFINER SET search_path = pg_catalog, skyline, pg_temp"

ACTIVE_SESSION = """
    s.token_hash = p_token_hash
    AND s.revoked_at IS NULL
    AND s.expires_at > now()
    AND u.status = 'active'
    AND t.status = 'active'
"""

FUNCTIONS: dict[str, str] = {
    "current_tenant_id()": """
        CREATE FUNCTION skyline.current_tenant_id() RETURNS uuid
        LANGUAGE sql STABLE PARALLEL SAFE
        AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$
    """,
    # Login: one row per active membership of an active user. Unknown, disabled and
    # tenant-less users all return no rows (the API then verifies against a dummy hash).
    "auth_lookup_user(text)": f"""
        CREATE FUNCTION skyline.auth_lookup_user(p_email text)
        RETURNS TABLE (user_id uuid, password_hash text, must_change_password boolean,
                       tenant_id uuid, role text)
        LANGUAGE sql STABLE {DEFINER}
        AS $$
            SELECT u.id, u.password_hash, u.must_change_password, m.tenant_id, m.role
            FROM skyline.users u
            JOIN skyline.memberships m ON m.user_id = u.id
            JOIN skyline.tenants t ON t.id = m.tenant_id
            WHERE u.email = p_email AND u.status = 'active' AND t.status = 'active'
            ORDER BY m.created_at, m.tenant_id
        $$
    """,
    # Every request: a session only resolves if it is live, not idle, and its user, tenant
    # and membership are all still active. Fails closed.
    "resolve_session(bytea,interval)": f"""
        CREATE FUNCTION skyline.resolve_session(p_token_hash bytea, p_idle interval)
        RETURNS TABLE (session_id uuid, tenant_id uuid, user_id uuid, created_at timestamptz,
                       last_seen_at timestamptz, expires_at timestamptz,
                       must_change_password boolean, role text)
        LANGUAGE sql STABLE {DEFINER}
        AS $$
            SELECT s.id, s.tenant_id, s.user_id, s.created_at, s.last_seen_at, s.expires_at,
                   u.must_change_password, m.role
            FROM skyline.sessions s
            JOIN skyline.users u ON u.id = s.user_id
            JOIN skyline.tenants t ON t.id = s.tenant_id
            JOIN skyline.memberships m ON m.tenant_id = s.tenant_id AND m.user_id = s.user_id
            WHERE {ACTIVE_SESSION}
              AND s.last_seen_at > now() - LEAST(p_idle, interval '1 day')
        $$
    """,
    # Password change is bound to a live session: it can only change the password of the
    # session's own user, never of another user by ID. It revokes all that user's sessions.
    "change_password(bytea,text,interval)": f"""
        CREATE FUNCTION skyline.change_password(
            p_token_hash bytea, p_new_hash text, p_idle interval)
        RETURNS uuid
        LANGUAGE plpgsql VOLATILE {DEFINER}
        AS $$
        DECLARE
            v_user uuid;
        BEGIN
            IF p_new_hash IS NULL OR p_new_hash NOT LIKE '$argon2id$%'
               OR length(p_new_hash) > 512 THEN
                RAISE EXCEPTION 'invalid password hash' USING ERRCODE = '22023';
            END IF;
            SELECT s.user_id INTO v_user
            FROM skyline.sessions s
            JOIN skyline.users u ON u.id = s.user_id
            JOIN skyline.tenants t ON t.id = s.tenant_id
            WHERE {ACTIVE_SESSION}
              AND s.last_seen_at > now() - LEAST(p_idle, interval '1 day');
            IF v_user IS NULL THEN
                RETURN NULL;
            END IF;
            UPDATE skyline.users
               SET password_hash = p_new_hash, must_change_password = false,
                   password_changed_at = now()
             WHERE id = v_user;
            UPDATE skyline.sessions SET revoked_at = now()
             WHERE user_id = v_user AND revoked_at IS NULL;
            RETURN v_user;
        END
        $$
    """,
    # Throttling is check-and-reserve in one step (API review H1): the subject locks make the
    # count and the reservation atomic, so parallel requests can't all pass the check while
    # the password is being hashed. The reservation counts as a failure until finished.
    "begin_login_attempt(bytea,integer,bytea,integer,interval)": f"""
        CREATE FUNCTION skyline.begin_login_attempt(
            p_account bytea, p_account_limit integer, p_ip bytea, p_ip_limit integer,
            p_window interval)
        RETURNS TABLE (allowed boolean, retry_after integer, attempt_ids bigint[])
        LANGUAGE plpgsql VOLATILE {DEFINER}
        AS $$
        DECLARE
            v_window interval := LEAST(p_window, interval '1 day');
            v_failures integer;
            v_oldest timestamptz;
            v_ids bigint[] := ARRAY[]::bigint[];
            v_id bigint;
        BEGIN
            -- Each statement must see rows committed while we waited for the locks.
            IF current_setting('transaction_isolation') <> 'read committed' THEN
                RAISE EXCEPTION 'begin_login_attempt needs READ COMMITTED' USING ERRCODE = '25001';
            END IF;
            IF p_account IS NULL OR coalesce(p_account_limit, 0) < 1
               OR (p_ip IS NOT NULL AND coalesce(p_ip_limit, 0) < 1) THEN
                RAISE EXCEPTION 'subjects need positive limits' USING ERRCODE = '22023';
            END IF;
            -- Fixed order (account, then IP) keeps concurrent callers deadlock-free.
            -- Never queue: a subject that is busy right now is told to retry in a second,
            -- so floods can't pile up waiters holding database connections.
            IF NOT pg_try_advisory_xact_lock(
                    hashtextextended('skyline.login.account:' || encode(p_account, 'hex'), 0))
               OR (p_ip IS NOT NULL AND NOT pg_try_advisory_xact_lock(
                    hashtextextended('skyline.login.ip:' || encode(p_ip, 'hex'), 0))) THEN
                RETURN QUERY SELECT false, 1, ARRAY[]::bigint[];
                RETURN;
            END IF;
            SELECT f.failures, f.oldest INTO v_failures, v_oldest
              FROM skyline.recent_login_failures('account', p_account, v_window, true) f;
            IF v_failures >= p_account_limit THEN
                RETURN QUERY SELECT false, GREATEST(1, ceil(extract(epoch FROM
                    v_oldest + v_window - clock_timestamp()))::integer), ARRAY[]::bigint[];
                RETURN;
            END IF;
            IF p_ip IS NOT NULL THEN
                SELECT f.failures, f.oldest INTO v_failures, v_oldest
                  FROM skyline.recent_login_failures('ip', p_ip, v_window, false) f;
                IF v_failures >= p_ip_limit THEN
                    RETURN QUERY SELECT false, GREATEST(1, ceil(extract(epoch FROM
                        v_oldest + v_window - clock_timestamp()))::integer), ARRAY[]::bigint[];
                    RETURN;
                END IF;
            END IF;
            INSERT INTO skyline.login_attempts (subject_type, subject_hash, succeeded)
            VALUES ('account', p_account, false) RETURNING id INTO v_id;
            v_ids := v_ids || v_id;
            IF p_ip IS NOT NULL THEN
                INSERT INTO skyline.login_attempts (subject_type, subject_hash, succeeded)
                VALUES ('ip', p_ip, false) RETURNING id INTO v_id;
                v_ids := v_ids || v_id;
            END IF;
            RETURN QUERY SELECT true, 0, v_ids;
        END
        $$
    """,
    # 'succeeded' flips a reservation (a success resets the account budget); 'cancelled'
    # drops it (the request never got to check a password); 'failed' keeps it as is. Only
    # recent rows can change.
    "finish_login_attempt(bigint[],text)": f"""
        CREATE FUNCTION skyline.finish_login_attempt(p_ids bigint[], p_outcome text)
        RETURNS void
        LANGUAGE plpgsql VOLATILE {DEFINER}
        AS $$
        BEGIN
            IF p_outcome = 'succeeded' THEN
                UPDATE skyline.login_attempts SET succeeded = true
                 WHERE id = ANY(p_ids) AND NOT succeeded
                   AND at > now() - interval '15 minutes';
            ELSIF p_outcome = 'cancelled' THEN
                DELETE FROM skyline.login_attempts
                 WHERE id = ANY(p_ids) AND NOT succeeded
                   AND at > now() - interval '15 minutes';
            ELSIF p_outcome IS DISTINCT FROM 'failed' THEN
                RAISE EXCEPTION 'unknown outcome' USING ERRCODE = '22023';
            END IF;
        END
        $$
    """,
    "recent_login_failures(text,bytea,interval,boolean)": f"""
        CREATE FUNCTION skyline.recent_login_failures(
            p_subject_type text, p_subject_hash bytea, p_window interval,
            p_reset_on_success boolean)
        RETURNS TABLE (failures integer, oldest timestamptz)
        LANGUAGE sql STABLE {DEFINER}
        AS $$
            SELECT count(*)::integer, min(a.at)
            FROM skyline.login_attempts a
            WHERE a.subject_type = p_subject_type AND a.subject_hash = p_subject_hash
              AND NOT a.succeeded
              AND a.at > now() - LEAST(p_window, interval '1 day')
              AND (NOT p_reset_on_success OR a.at > COALESCE((
                    SELECT max(b.at) FROM skyline.login_attempts b
                    WHERE b.subject_type = p_subject_type AND b.subject_hash = p_subject_hash
                      AND b.succeeded), '-infinity'::timestamptz))
        $$
    """,
    "purge_login_attempts()": f"""
        CREATE FUNCTION skyline.purge_login_attempts() RETURNS integer
        LANGUAGE sql VOLATILE {DEFINER}
        AS $$
            WITH purged AS (
                DELETE FROM skyline.login_attempts WHERE at < now() - interval '1 day'
                RETURNING 1
            )
            SELECT count(*)::integer FROM purged
        $$
    """,
    "due_integrations(integer)": f"""
        CREATE FUNCTION skyline.due_integrations(p_limit integer)
        RETURNS TABLE (tenant_id uuid, integration_id uuid)
        LANGUAGE sql STABLE {DEFINER}
        AS $$
            SELECT i.tenant_id, i.id FROM skyline.integrations i
            JOIN skyline.tenants t ON t.id = i.tenant_id
            WHERE i.status = 'connected' AND i.deleted_at IS NULL AND t.status = 'active'
              AND i.next_scan_at IS NOT NULL AND i.next_scan_at <= now()
            ORDER BY i.next_scan_at
            LIMIT LEAST(GREATEST(p_limit, 1), 1000)
        $$
    """,
    # ADR-0011: no inbound request can mark an integration connected; only the worker (or the
    # owner, for maintenance) can. Changing a connected integration's config re-verifies it.
    "integrations_guard_status()": """
        CREATE FUNCTION skyline.integrations_guard_status() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            IF current_user IN ('skyline_worker', 'skyline_owner') THEN
                RETURN NEW;
            END IF;
            IF TG_OP = 'UPDATE' THEN
                IF NEW.credential_secret_id IS NOT NULL
                   AND NEW.credential_secret_id IS DISTINCT FROM OLD.credential_secret_id THEN
                    RAISE EXCEPTION 'an integration credential can only be removed'
                        USING ERRCODE = '42501';
                END IF;
                IF OLD.status = 'connected' AND NEW.config IS DISTINCT FROM OLD.config THEN
                    NEW.status := 'verifying';
                END IF;
                IF NEW.status = 'connected' AND OLD.status IS DISTINCT FROM 'connected' THEN
                    RAISE EXCEPTION 'only the worker may mark an integration connected'
                        USING ERRCODE = '42501';
                END IF;
            ELSIF NEW.status = 'connected' THEN
                RAISE EXCEPTION 'only the worker may mark an integration connected'
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END
        $$
    """,
    # Revocation is one-way and timestamps can't be pushed into the future.
    "sessions_guard()": """
        CREATE FUNCTION skyline.sessions_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
                RAISE EXCEPTION 'a revoked session cannot be changed' USING ERRCODE = '42501';
            END IF;
            IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
                NEW.revoked_at := now();
            END IF;
            NEW.last_seen_at := GREATEST(OLD.last_seen_at, LEAST(NEW.last_seen_at, now()));
            RETURN NEW;
        END
        $$
    """,
    "exceptions_guard()": """
        CREATE FUNCTION skyline.exceptions_guard() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
        AS $$
        BEGIN
            IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
               OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by) THEN
                RAISE EXCEPTION 'a revoked exception cannot be changed' USING ERRCODE = '42501';
            END IF;
            IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
                NEW.revoked_at := now();
            END IF;
            RETURN NEW;
        END
        $$
    """,
}

FUNCTION_GRANTS: dict[str, tuple[str, ...]] = {
    "current_tenant_id()": ("skyline_api", "skyline_worker", "skyline_definer"),
    "auth_lookup_user(text)": ("skyline_api",),
    "resolve_session(bytea,interval)": ("skyline_api",),
    "change_password(bytea,text,interval)": ("skyline_api",),
    "begin_login_attempt(bytea,integer,bytea,integer,interval)": ("skyline_api",),
    "finish_login_attempt(bigint[],text)": ("skyline_api",),
    # Internal helper of begin_login_attempt: no direct callers.
    "recent_login_failures(text,bytea,interval,boolean)": (),
    "purge_login_attempts()": ("skyline_worker",),
    "due_integrations(integer)": ("skyline_worker",),
    "integrations_guard_status()": (),
    "sessions_guard()": (),
    "exceptions_guard()": (),
}

TRIGGERS: tuple[tuple[str, str, str], ...] = (
    ("integrations_guard_status", "integrations", "INSERT OR UPDATE"),
    ("sessions_guard", "sessions", "UPDATE"),
    ("exceptions_guard", "exceptions", "UPDATE"),
)

DEFINER_OWNED = tuple(n for n, ddl in FUNCTIONS.items() if "SECURITY DEFINER" in ddl)

TABLE_GRANTS: tuple[str, ...] = (
    # ---------------------------------------------------------------- api
    "GRANT SELECT (id, email, must_change_password, status, password_changed_at,"
    " last_login_at, created_at) ON skyline.users TO skyline_api",
    "GRANT UPDATE (last_login_at) ON skyline.users TO skyline_api",
    "GRANT SELECT (id, slug, name, status, created_at) ON skyline.tenants TO skyline_api",
    "GRANT SELECT ON skyline.memberships TO skyline_api",
    "GRANT SELECT (id, tenant_id, user_id, created_at, last_seen_at, expires_at, revoked_at)"
    " ON skyline.sessions TO skyline_api",
    "GRANT INSERT (id, tenant_id, user_id, token_hash, expires_at) ON skyline.sessions"
    " TO skyline_api",
    "GRANT UPDATE (last_seen_at, revoked_at) ON skyline.sessions TO skyline_api",
    # Insert-only for key material: the API can seal a credential but never read it back.
    "GRANT INSERT (id, tenant_id, purpose, key_provider, key_id, wrapped_dek, nonce,"
    " ciphertext, format_version) ON skyline.secrets TO skyline_api",
    "GRANT SELECT (id, tenant_id, purpose, key_provider, key_id, format_version, created_at)"
    " ON skyline.secrets TO skyline_api",
    "GRANT SELECT ON skyline.integrations TO skyline_api",
    "GRANT INSERT (id, tenant_id, provider, name, config, status, credential_secret_id,"
    " scan_interval, created_by) ON skyline.integrations TO skyline_api",
    "GRANT UPDATE (name, config, status, status_detail, scan_interval, next_scan_at,"
    " deleted_at, updated_at, credential_secret_id) ON skyline.integrations TO skyline_api",
    "GRANT DELETE ON skyline.secrets TO skyline_api",
    "GRANT INSERT (id, tenant_id, kind, integration_id, payload, max_attempts)"
    " ON skyline.jobs TO skyline_api",
    "GRANT SELECT ON skyline.scan_runs TO skyline_api",
    "GRANT INSERT (id, tenant_id, integration_id, trigger, requested_by)"
    " ON skyline.scan_runs TO skyline_api",
    "GRANT SELECT ON skyline.assets, skyline.relationships, skyline.findings,"
    " skyline.finding_events TO skyline_api",
    "GRANT SELECT ON skyline.exceptions TO skyline_api",
    "GRANT INSERT (id, tenant_id, scope_type, finding_id, check_id, asset_id, justification,"
    " created_by, approved_by, expires_at) ON skyline.exceptions TO skyline_api",
    "GRANT UPDATE (revoked_at, revoked_by) ON skyline.exceptions TO skyline_api",
    # ---------------------------------------------------------------- worker
    "GRANT SELECT (id, status, redaction_key_secret_id) ON skyline.tenants TO skyline_worker",
    "GRANT SELECT ON skyline.secrets TO skyline_worker",
    "GRANT SELECT ON skyline.integrations TO skyline_worker",
    "GRANT UPDATE (status, status_detail, next_scan_at, last_scan_at, template_version,"
    " updated_at) ON skyline.integrations TO skyline_worker",
    "GRANT SELECT ON skyline.jobs TO skyline_worker",
    "GRANT INSERT (id, tenant_id, kind, integration_id, payload, max_attempts, run_at)"
    " ON skyline.jobs TO skyline_worker",
    "GRANT UPDATE (status, attempts, run_at, lease_expires_at, locked_by, last_error,"
    " updated_at, finished_at) ON skyline.jobs TO skyline_worker",
    "GRANT SELECT ON skyline.scan_runs TO skyline_worker",
    "GRANT INSERT (id, tenant_id, integration_id, trigger, requested_by)"
    " ON skyline.scan_runs TO skyline_worker",
    "GRANT UPDATE (status, started_at, finished_at, stats, scope_errors)"
    " ON skyline.scan_runs TO skyline_worker",
    "GRANT SELECT, INSERT, UPDATE ON skyline.assets, skyline.relationships, skyline.findings"
    " TO skyline_worker",
    "GRANT SELECT, INSERT ON skyline.finding_events TO skyline_worker",
    # ---------------------------------------------------------------- both
    "GRANT SELECT ON skyline.audit_log TO skyline_api, skyline_worker",
    # id and at are server-generated so neither role can forge the order or time of events.
    "GRANT INSERT (tenant_id, actor_type, actor_id, action, outcome, target_type, target_id,"
    " details, ip, correlation_id) ON skyline.audit_log TO skyline_api, skyline_worker",
    "GRANT SELECT ON skyline.checks, skyline.frameworks, skyline.controls,"
    " skyline.check_control_map, skyline.alembic_version TO skyline_api, skyline_worker",
    # ---------------------------------------------------------------- definer
    "GRANT SELECT ON skyline.users, skyline.tenants, skyline.memberships, skyline.sessions,"
    " skyline.integrations TO skyline_definer",
    "GRANT UPDATE (password_hash, must_change_password, password_changed_at)"
    " ON skyline.users TO skyline_definer",
    "GRANT UPDATE (revoked_at) ON skyline.sessions TO skyline_definer",
    "GRANT SELECT, INSERT, DELETE ON skyline.login_attempts TO skyline_definer",
    "GRANT UPDATE (succeeded) ON skyline.login_attempts TO skyline_definer",
)

SEQUENCE_GRANTS: tuple[tuple[str, str], ...] = (
    ("skyline.audit_log", "skyline_api, skyline_worker"),
    ("skyline.finding_events", "skyline_worker"),
    ("skyline.login_attempts", "skyline_definer"),
)

MEMBER_OF_TENANT = (
    "EXISTS (SELECT 1 FROM skyline.memberships m"
    " WHERE m.user_id = users.id AND m.tenant_id = skyline.current_tenant_id())"
)

# (name, table, statement)
POLICIES: tuple[tuple[str, str, str], ...] = (
    # users: only members of the current tenant are visible or updatable.
    ("users_member_read", "users", f"FOR SELECT USING ({MEMBER_OF_TENANT})"),
    (
        "users_member_update",
        "users",
        f"FOR UPDATE USING ({MEMBER_OF_TENANT}) WITH CHECK ({MEMBER_OF_TENANT})",
    ),
    ("users_definer", "users", "TO skyline_definer USING (true) WITH CHECK (true)"),
    ("users_owner", "users", "TO skyline_owner USING (true) WITH CHECK (true)"),
    # tenants: an app role sees only its current tenant.
    ("tenants_current", "tenants", "FOR SELECT USING (id = skyline.current_tenant_id())"),
    ("tenants_definer", "tenants", "FOR SELECT TO skyline_definer USING (true)"),
    ("tenants_owner", "tenants", "TO skyline_owner USING (true) WITH CHECK (true)"),
    # audit_log: tenant rows for everyone; tenant-less rows only for pre-auth login events
    # from the API, and platform events from the owner (which alone can read them).
    ("audit_read", "audit_log", "FOR SELECT USING (tenant_id = skyline.current_tenant_id())"),
    (
        "audit_insert",
        "audit_log",
        "FOR INSERT WITH CHECK (tenant_id = skyline.current_tenant_id())",
    ),
    (
        "audit_insert_preauth",
        "audit_log",
        "FOR INSERT TO skyline_api WITH CHECK (tenant_id IS NULL AND actor_type = 'anonymous'"
        " AND action IN ('auth.login.failed', 'auth.login.throttled'))",
    ),
    ("audit_owner", "audit_log", "TO skyline_owner USING (true) WITH CHECK (true)"),
    # secrets: the API may only ever seal integration credentials (never redaction keys).
    (
        "secrets_api_credentials_only",
        "secrets",
        "AS RESTRICTIVE FOR INSERT TO skyline_api WITH CHECK (purpose = 'integration_credential')",
    ),
    (
        "secrets_api_delete_credentials_only",
        "secrets",
        "AS RESTRICTIVE FOR DELETE TO skyline_api USING (purpose = 'integration_credential')",
    ),
    # integrations: the API can't create an already-connected integration.
    (
        "integrations_api_not_connected",
        "integrations",
        "AS RESTRICTIVE FOR INSERT TO skyline_api WITH CHECK (status <> 'connected')",
    ),
    # jobs: the worker claims and reaps jobs of every tenant; payloads hold IDs only.
    ("jobs_worker", "jobs", "TO skyline_worker USING (true) WITH CHECK (true)"),
    # Pre-tenant lookups, reachable only through the definer functions above.
    ("definer_read", "sessions", "FOR SELECT TO skyline_definer USING (true)"),
    ("definer_revoke", "sessions", "FOR UPDATE TO skyline_definer USING (true) WITH CHECK (true)"),
    ("definer_read", "memberships", "FOR SELECT TO skyline_definer USING (true)"),
    ("definer_read", "integrations", "FOR SELECT TO skyline_definer USING (true)"),
)

DATABASE_PRIVILEGES_UP = """
    DO $$ BEGIN
        EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO skyline_api, skyline_worker',
                       current_database());
    END $$
"""

DATABASE_PRIVILEGES_DOWN = """
    DO $$ BEGIN
        EXECUTE format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO PUBLIC', current_database());
    END $$
"""


def upgrade() -> None:
    op.execute(DATABASE_PRIVILEGES_UP)
    op.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    op.execute("REVOKE ALL ON SCHEMA skyline FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA skyline TO skyline_api, skyline_worker, skyline_definer")
    # Functions created by later migrations are not executable by PUBLIC by default.
    op.execute("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
    op.execute("SET LOCAL ROLE skyline_definer")
    op.execute("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
    op.execute("RESET ROLE")

    for name, ddl in FUNCTIONS.items():
        op.execute(ddl)
        op.execute(f"REVOKE ALL ON FUNCTION skyline.{name} FROM PUBLIC")
        if FUNCTION_GRANTS[name]:
            roles = ", ".join(FUNCTION_GRANTS[name])
            op.execute(f"GRANT EXECUTE ON FUNCTION skyline.{name} TO {roles}")

    # Hand the definer functions to the NOLOGIN definer role (grants above are kept). The
    # definer needs CREATE on the schema only for the ownership change.
    op.execute("GRANT CREATE ON SCHEMA skyline TO skyline_definer")
    for name in DEFINER_OWNED:
        op.execute(f"ALTER FUNCTION skyline.{name} OWNER TO skyline_definer")
    op.execute("REVOKE CREATE ON SCHEMA skyline FROM skyline_definer")

    for trigger, table, events in TRIGGERS:
        op.execute(
            f"CREATE TRIGGER {trigger} BEFORE {events} ON skyline.{table}"
            f" FOR EACH ROW EXECUTE FUNCTION skyline.{trigger}()"
        )

    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE skyline.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE skyline.{table} FORCE ROW LEVEL SECURITY")
    for table in TENANT_TABLES:
        op.execute(
            f"CREATE POLICY tenant_isolation ON skyline.{table}"
            " USING (tenant_id = skyline.current_tenant_id())"
            " WITH CHECK (tenant_id = skyline.current_tenant_id())"
        )
    for name, table, statement in POLICIES:
        op.execute(f"CREATE POLICY {name} ON skyline.{table} {statement}")

    for statement in TABLE_GRANTS:
        op.execute(statement)
    for table, roles in SEQUENCE_GRANTS:
        op.execute(
            "DO $$ BEGIN EXECUTE format('GRANT USAGE ON SEQUENCE %s TO "
            f"{roles}', pg_get_serial_sequence('{table}', 'id')); END $$"
        )


def downgrade() -> None:
    for role in ("skyline_api", "skyline_worker", "skyline_definer"):
        op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA skyline FROM {role}")
        op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA skyline FROM {role}")
    for name, table, _ in POLICIES:
        op.execute(f"DROP POLICY IF EXISTS {name} ON skyline.{table}")
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON skyline.{table}")
    for table in RLS_TABLES:
        op.execute(f"ALTER TABLE skyline.{table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE skyline.{table} DISABLE ROW LEVEL SECURITY")
    for trigger, table, _ in TRIGGERS:
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON skyline.{table}")
    # Only the owning role may drop a function; the owner can SET ROLE to the definer.
    op.execute("SET LOCAL ROLE skyline_definer")
    for name in DEFINER_OWNED:
        op.execute(f"DROP FUNCTION IF EXISTS skyline.{name}")
    op.execute("ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO PUBLIC")
    op.execute("RESET ROLE")
    for name in FUNCTIONS:
        if name not in DEFINER_OWNED:
            op.execute(f"DROP FUNCTION IF EXISTS skyline.{name}")
    op.execute("ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO PUBLIC")
    op.execute("REVOKE USAGE ON SCHEMA skyline FROM skyline_api, skyline_worker, skyline_definer")
    op.execute("GRANT USAGE ON SCHEMA public TO PUBLIC")
    op.execute(DATABASE_PRIVILEGES_DOWN)
