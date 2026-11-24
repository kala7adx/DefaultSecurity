# Phase 0 web, deployment and CI: security review

Reviewer: `security-reviewer` agent, 2026-11-24, on apps/web, deploy/, secrets-init and
.github/ before their first commit. One round plus a final check. **Status: fixed; final check
OK.**

| Finding | Fix | Test |
|---|---|---|
| **H1** open redirect via dot segments in `?next=` (`/..//evil.example` resolves to `//evil.example`) | `safeNext` rejects `.`/`..` segments and re-checks the parsed output (single leading `/`, no backslash, no control characters). A 300,000-case fuzz found nothing escaping the origin. | `safe-next.test.ts` (reviewer payloads + more) |
| **M1** licence gates were deny lists that missed AGPL classifier text, UNLICENSED, SEE LICENSE IN, Elastic-2.0 | `scripts/check_licences.py`: an allowlist with a real SPDX parser (brackets, AND before OR, WITH rejected); fails closed on unknown text and empty input; workspace packages matched by exact name; CC-BY-4.0 only for `caniuse-lite`; CI steps run with pipefail. | `scripts/tests/test_check_licences.py` |
| **L1** `.dockerignore` matched `.env` only at the root | `**/.env`, `**/.env.*`, `**/*.verifier`, `**/kek*.json`. | — |
| **L2** one flat Compose network | `frontend` (web, api), `backend` (internal: api, worker, migrate, postgres), `egress` (worker). | smoke test on the split networks |
| **L3** hops=0 shares one login IP bucket | Documented in Compose: fine on 127.0.0.1; put an appending edge proxy in front and set 1 before exposing it. | — |
| **L4** runtime user owned the app code; package managers in images | Code copied root-owned; pip/setuptools/ensurepip and npm/npx/corepack/yarn removed from runtime stages (also clears their HIGH CVEs). | Trivy: 0 fixable HIGH/CRITICAL on both images |
| **L5** pnpm and pip-audit not pinned by checksum | pnpm tarball verified against a pinned SHA-512 (matches registry integrity); pip-audit in the locked uv dev group. | image build |
| **L6** ARG-based FROM lines invisible to Dependabot; scanner digests untracked | Literal `FROM image@sha256:…`; scanner digests documented as a monthly manual bump; Dependabot cooldown 7 days. | — |
| **L7** `p/owasp-top-ten` missing | Added to the semgrep step. | semgrep run locally: clean after triage |
| **L8** CSP gaps (`/api…` paths, prefetches) | Proxy excludes only `api/v1/`; a static baseline CSP on every response; `base-uri 'none'`. | smoke test + browser check |
| **L9** Playwright could record or fix the admin password | Traces off; random new password unless set; test output and build artefacts git-ignored. | — |

Supply-chain additions from the semgrep run: pnpm `minimumReleaseAge` (3 days),
`trustPolicy: no-downgrade` and `blockExoticSubdeps`. The fresh resolution moved
`@tanstack/react-query` to 5.108.2 and `caniuse-lite` back one release. One reviewed exception:
`eslint-import-resolver-typescript@3.10.1` (dev-only, same long-standing maintainer as 3.10.0,
registry-signed, published 2025-04-21; neither 3.10.x has provenance).
