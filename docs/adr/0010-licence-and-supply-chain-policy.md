# 0010. Licence and software supply-chain policy

- Status: Accepted (owner decisions 2026-11-23); action SHAs and tool versions are filled in when CI is built
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Skyline is Apache-2.0 open source. `CLAUDE.md` allows dependencies under
Apache-2.0/MIT/BSD/ISC/MPL-2.0 and requires flagging AGPL/GPL/BSL/SSPL. Next.js and the Python
typing stack pull in transitive packages under other permissive licences, and Next.js depends on
`caniuse-lite`, which is CC-BY-4.0 data. `SECURE_CODING.md` requires semgrep, CodeQL, gitleaks,
pip-audit, pnpm audit, Trivy, SBOMs, SHA-pinned actions and OpenSSF Scorecard. In March 2026,
attackers rewrote most version tags of `aquasecurity/trivy-action` and `setup-trivy` to deliver
a CI secret stealer. Only SHA-pinned consumers were safe.

## Decision
- **Licence allowlist**, enforced in CI by `pip-licenses` for Python and `pnpm licenses list` for
  Node, against a checked-in allowlist:
  - Direct and transitive: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0.
  - Transitive, permissive (owner-approved): PSF-2.0 / Python-2.0, 0BSD, MIT-0, Unlicense,
    CC0-1.0, BlueOak-1.0.0, and CC-BY-4.0 for data packages.
  - **Blocked:** GPL, LGPL, AGPL, SSPL, BSL/BUSL, the Commons Clause, and unknown or missing
    licences. Any exception needs the owner's approval and an entry in `THIRD_PARTY.md`.
- **CI-only tools** never ship in Skyline images, are recorded separately in `THIRD_PARTY.md`,
  and run from pinned containers or binaries:
  - semgrep CE: engine LGPL-2.1, registry rules under the Semgrep Rules License (internal use).
    Owner-approved.
  - gitleaks (MIT), Trivy (Apache-2.0), Syft (Apache-2.0), CodeQL (GitHub-hosted, free for
    public repos), cfn-lint (MIT-0), checkov (Apache-2.0).
- **Pinning:**
  - `uv.lock` and `pnpm-lock.yaml` are committed. CI uses `uv sync --locked` and
    `pnpm install --frozen-lockfile`.
  - Every GitHub Action is referenced by **full commit SHA** with a version comment. Dependabot
    updates SHAs.
  - Tool binaries (Trivy, Syft, gitleaks) are pinned by version **and checksum**, or by image
    digest.
  - Base images are pinned by digest.
  - Trivy runs from a verified, pinned release. We don't use `trivy-action` tags.
- **Workflow hygiene:**
  - `permissions: contents: read` by default, elevated per job only where needed (for example
    `security-events: write` for SARIF).
  - No `pull_request_target` that checks out PR code. Forked PRs get no secrets.
  - CODEOWNERS on `.github/` and `deploy/`.
- **Dependencies:** each new direct dependency gets a justification in its commit message:
  purpose, licence, maintenance status and adoption. Dependabot runs weekly for uv, npm,
  github-actions and docker.
- **Releases (Phase 4):** tagged images signed with cosign keyless, with an SBOM (Syft) and
  provenance attestation. The OpenSSF Scorecard target is 8 or higher.

## Consequences
- Licence or supply-chain drift fails CI instead of surfacing at release.
- SHA pins need Dependabot to stay current; that's an accepted maintenance cost.

## Alternatives considered
- Strict five-licence list: would rule out Next.js (caniuse-lite) and much of the ecosystem.
- Dropping semgrep and relying on CodeQL + bandit: a weaker OWASP rule coverage. The owner chose
  to keep semgrep as a CI-only tool.

## References
- Trivy GitHub Actions compromise advisory (GHSA-69fq-xp46-6x23): https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- GitHub Actions security hardening: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- Semgrep Rules License: https://semgrep.dev/legal/rules-license
