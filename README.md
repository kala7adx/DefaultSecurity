# Skyline

Skyline is an open-source, self-hostable, **agentless cloud and SaaS security posture platform**
(CSPM + SSPM, growing toward CNAPP). It connects read-only to cloud accounts and SaaS tenants,
builds an asset inventory and relationship graph, runs policy checks, and produces prioritised
findings mapped to compliance frameworks (Cyber Essentials, ISO 27001:2022, CIS, NIST CSF 2.0).

> **Status: Phase 0 (walking skeleton).** Only the built-in `fake` connector exists. It
> simulates a small company so you can try the full flow without any cloud account.
> See [docs/ROADMAP.md](docs/ROADMAP.md).

## Quick start (Docker Compose)

Requirements: Docker Desktop or Docker Engine with Compose v2.

1. Start everything (the first build takes a few minutes):

   ```sh
   docker compose -f deploy/compose/docker-compose.yml up --build -d --wait
   ```

   A one-shot `secrets-init` container generates every secret (database passwords, the
   key-encryption key, the session key, the first admin password) into a Docker volume.
   Nothing secret is in the repository or the Compose file.

2. Read the generated admin password once (it is never logged):

   ```sh
   docker compose -f deploy/compose/docker-compose.yml run --rm --no-deps -T --entrypoint cat secrets-init /secrets/admin/bootstrap_admin_password
   ```

3. Open <http://localhost:3000> (bound to 127.0.0.1 only) and sign in as `admin@example.com`
   with that password. You must choose a new password (12+ characters) straight away.

4. **Integrations → Add demo company.** Skyline verifies it, runs the first scan and shows
   five findings, each mapped to Cyber Essentials v3.3 and/or ISO 27001:2022 controls.

5. **Simulate fixes**, then watch the findings auto-resolve after the rescan. **Undo** reopens
   them. Every action is in the audit log.

To start over: `docker compose -f deploy/compose/docker-compose.yml down -v` (deletes the
database and the generated secrets).

### Developing

```sh
uv sync && uv run pytest                    # backend tests (needs Docker for PostgreSQL)
uv run ruff check . && uv run mypy && uv run mypy packages
pnpm install && pnpm --dir apps/web lint && pnpm --dir apps/web test
```

## Documentation

- [Product brief](docs/PRODUCT_BRIEF.md)
- [Architecture](docs/ARCHITECTURE.md) and [ADRs](docs/adr/README.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Secure coding standard](docs/SECURE_CODING.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [THIRD_PARTY.md](THIRD_PARTY.md).
