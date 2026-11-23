# Secure Coding & Code Hygiene Standard

Applies to every change in this repo, by humans or Claude Code. Target: **OWASP ASVS 5.0 Level 2**
for the API and web app, **OWASP Top 10 / API Security Top 10** as the review checklist, and
**OpenSSF Scorecard** best practices for the repo and supply chain. Where this file and convenience
disagree, this file wins. Exceptions need an ADR.

---

## 1. Secure coding rules

### Input, output and data handling
- Validate every external input at the boundary with Pydantic models (API bodies, query params,
  headers, connector API responses, YAML check files). Reject unknown fields (`extra="forbid"`).
- Database access only through SQLAlchemy expressions or bound parameters. **No string-built SQL.**
- Never use `eval`, `exec`, `pickle`, `marshal`, `shelve`, `yaml.load` (use `yaml.safe_load`),
  or `jsonpickle` on anything that could be influenced from outside.
- `subprocess` only with an argument list, never `shell=True`, never with user-controlled input.
- File paths from input are resolved and checked against an allowed base directory.
- Web app: rely on React escaping; never `dangerouslySetInnerHTML` without a sanitiser (DOMPurify)
  and a comment explaining why. Strict Content-Security-Policy, no inline scripts.

### Outbound requests (SSRF and reliability)
- Every HTTP client has an explicit timeout, retry policy with jittered backoff, and TLS
  verification **on** (never `verify=False`).
- User-supplied URLs (webhooks, Jira, custom endpoints) go through an SSRF guard: https only,
  resolve DNS and block private, loopback, link-local and cloud metadata ranges
  (`169.254.169.254`, `fd00:ec2::254`), re-check after redirects, cap response size.

### AuthN / AuthZ
- Deny by default. Every API route declares its required permission; a test enumerates all routes
  and fails if one has no explicit permission (except health endpoints).
- Every query on tenant-owned data is tenant-scoped **and** protected by Postgres RLS.
  IDOR tests for every resource endpoint (tenant A cannot read tenant B by ID).
- Passwords: argon2id. Sessions/JWT: short-lived, signed with rotated keys, audience/issuer checked,
  `alg` pinned. Cookies `HttpOnly`, `Secure`, `SameSite=Lax` or stricter. CSRF protection on
  cookie-authenticated state-changing requests. Rate-limit login and token endpoints.

### Secrets and cryptography
- No secrets in code, fixtures, tests, logs, error messages, URLs or commit history.
  Config via environment variables; `.env.example` holds placeholders only.
- Use vetted libraries only (`cryptography`, cloud KMS SDKs). No home-made crypto, no static IVs or
  nonces, no MD5/SHA1 for security purposes. Constant-time comparison for tokens.
- Collected cloud data is customer data: redact secret-bearing fields before storage
  (see CLAUDE.md rule 4) and never send it to third-party services.

### Errors and logging
- Users see generic error messages with a correlation ID; details go to structured logs only.
- No stack traces, SQL or internal paths in API responses.
- Use the shared redaction logger. Never log request bodies, tokens, headers like `Authorization`,
  or raw resource config. Log security events (login, permission denied, integration changes)
  to the audit log.

### Connectors (product-specific)
- Read-only API allowlist per connector, enforced by test (CLAUDE.md rule 1).
- Least-privilege onboarding templates; every permission/scope has a comment explaining why.
- Treat API responses as untrusted input: validate shape, cap sizes, handle pagination limits.

### Containers and IaC
- Pinned base images by digest, non-root user, read-only root filesystem, no secrets in layers,
  `HEALTHCHECK`, minimal packages. Multi-stage builds.
- Terraform: no wildcard actions/resources/principals; encryption on by default; tfsec/checkov
  (or Trivy config) clean in CI.

## 2. Code hygiene rules

- **Typing:** full type hints; `mypy --strict` on `packages/`; TypeScript `strict: true`,
  no `any` without a comment.
- **Formatting/linting:** `ruff format` + `ruff check` (enable rule sets: E, F, I, B, S (bandit),
  UP, SIM, C4, RET, PTH, N, ASYNC, PL, RUF; max complexity 10), eslint + prettier for TS.
  Zero warnings policy in CI.
- **Tests:** pytest with coverage gate **≥ 85% on `packages/`** and ≥ 70% overall; every check has
  pass and fail fixtures; every bug fix comes with a regression test. Security-relevant code
  (auth, tenancy, crypto, redaction, SSRF guard, allowlist) needs explicit negative tests.
- **Design:** small functions, single responsibility, no global mutable state, dependency
  injection for clients so they can be faked in tests. Prefer the standard library and existing
  dependencies over adding new ones.
- **Dependencies:** lockfiles committed (`uv.lock`, `pnpm-lock.yaml`); new dependency requires a
  short justification in the PR/commit message (purpose, licence, maintenance status, downloads).
  Dependabot weekly; no abandoned packages.
- **Docs:** public functions and modules have docstrings; non-obvious decisions get a comment with
  the "why", vendor API details get a link to the official doc. No commented-out code.
  `TODO` only with a linked issue (`TODO(#12): ...`).
- **Commits:** Conventional Commits, small and focused; never mix refactors with behaviour changes.

## 3. Repository and CI guardrails (set up in Phase 0)

- `pre-commit`: ruff, ruff-format, mypy (fast subset), gitleaks, check-yaml/json/toml,
  end-of-file-fixer, trailing-whitespace, detect-private-key, eslint/prettier for web.
- CI on every PR and push to `main`:
  lint → types → tests with coverage gate → gitleaks → **CodeQL** (Python + JS/TS) →
  semgrep (p/owasp-top-ten, p/python, p/typescript) → pip-audit + pnpm audit →
  Docker build → Trivy image + config scan → SBOM (Syft) uploaded as artefact.
- GitHub Actions hygiene: actions **pinned to full commit SHAs**, `permissions:` set to the
  minimum per job (default `contents: read`), no `pull_request_target` with checkout of PR code,
  no secrets exposed to forked PRs.
- **OpenSSF Scorecard** workflow; aim for 8+.
- Repo files: `SECURITY.md` (private vulnerability reporting enabled), `CONTRIBUTING.md`,
  `CODEOWNERS`, `LICENSE` (Apache-2.0), `THIRD_PARTY.md`.
- Branch protection on `main`: PR required, all checks green, linear history, no force-push.
- Releases: tagged, images signed with cosign (keyless), SBOM and provenance attached.

## 4. Definition of Done (every change)

- [ ] Tests added/updated and passing, coverage gate met
- [ ] Lint, format and type checks clean with zero warnings
- [ ] No secrets, no new risky licences, new dependencies justified
- [ ] Security-relevant change reviewed by the `security-reviewer` agent, findings fixed
- [ ] Docs/ADRs/ROADMAP updated where behaviour or decisions changed
- [ ] Conventional Commit message
