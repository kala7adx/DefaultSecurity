# Security policy

Skyline holds read-only access to its users' cloud and SaaS accounts, so we treat security reports
as our top priority.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability reporting:
*Security → Report a vulnerability* on this repository. Include:

- the affected version or commit
- steps to reproduce, or a proof of concept
- the impact you believe it has

You can expect an acknowledgement within 5 working days and a status update at least every
14 days until it is resolved. We will credit you in the release notes unless you ask us not to.

## Scope

In scope: everything in this repository, including the API, worker, web UI, connectors,
onboarding templates, deployment files and CI workflows.

Out of scope: findings that need a compromised host, social engineering, or volumetric denial of
service.

## Supported versions

Skyline is pre-1.0. Only the latest commit on `main` receives security fixes.

## Design documents

The threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and the secure coding
standard in [docs/SECURE_CODING.md](docs/SECURE_CODING.md).
