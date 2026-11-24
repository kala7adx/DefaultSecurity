#!/bin/sh
# Runs once, when the PostgreSQL data volume is first initialised (docker-entrypoint-initdb.d).
# Creates the Skyline roles and database exactly as skyline_core.db.roles.create_roles does.
#
# Passwords never reach the server: secrets-init wrote SCRAM-SHA-256 verifiers, and psql
# passes them as variables quoted with :'name' (no SQL is built by the shell).
set -eu

dir=/run/skyline-secrets
for role in skyline_owner skyline_api skyline_worker; do
    [ -s "$dir/$role.verifier" ] || { echo "missing verifier for $role" >&2; exit 1; }
done

psql -v ON_ERROR_STOP=1 --no-psqlrc --quiet \
    --username "$POSTGRES_USER" --dbname postgres \
    -v owner_verifier="$(cat "$dir/skyline_owner.verifier")" \
    -v api_verifier="$(cat "$dir/skyline_api.verifier")" \
    -v worker_verifier="$(cat "$dir/skyline_worker.verifier")" <<'SQL'
\set attrs 'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
CREATE ROLE skyline_owner LOGIN :attrs PASSWORD :'owner_verifier';
CREATE ROLE skyline_api LOGIN :attrs PASSWORD :'api_verifier';
CREATE ROLE skyline_worker LOGIN :attrs PASSWORD :'worker_verifier';
CREATE ROLE skyline_definer NOLOGIN :attrs;
-- The owner hands functions to the definer role but must not inherit its privileges.
GRANT skyline_definer TO skyline_owner WITH INHERIT FALSE, SET TRUE;
CREATE DATABASE skyline OWNER skyline_owner;
SQL
echo "skyline roles and database created"
