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

```sh
docker compose -f deploy/compose/docker-compose.yml up --build
```

Quick-start steps are completed in the final Phase 0 slice.

## Documentation

- [Product brief](docs/PRODUCT_BRIEF.md)
- [Architecture](docs/ARCHITECTURE.md) and [ADRs](docs/adr/README.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Secure coding standard](docs/SECURE_CODING.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [THIRD_PARTY.md](THIRD_PARTY.md).
