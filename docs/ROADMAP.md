# Skyline — Roadmap

Source of scope: `docs/PRODUCT_BRIEF.md` (incl. §3a onboarding, §9 AWS reference deployment,
§11 end-state parity) and `prompts/01-PHASE-PROMPTS.md`. Order may change, but **nothing is
dropped without an ADR** (brief §11).

Status values: `Not started` · `Planning` · `In progress` · `Done` · `Blocked`.

| Phase | Theme | Status |
|---|---|---|
| 0 | Foundations: walking skeleton on a fake connector | **In progress** (design docs for review) |
| 1 | AWS connector, Orca-style onboarding, CIS AWS checks | Not started |
| 2 | Microsoft 365 / Entra ID / Exchange Online (SSPM) | Not started |
| 3 | Google Workspace (SSPM) | Not started |
| 4 | Deploy anywhere, incl. **Skyline-on-AWS reference** | Not started |
| 5 | Compliance and reporting | Not started |
| 6 | Azure and GCP connectors | Not started |
| 7 | Security graph and risk prioritisation | Not started |
| 8 | Agentless workload scanning (snapshot-based, VMs) | Not started |
| 9 | SaaS mode, SSO, integrations, scheduled scans and diffing | Not started |
| 10 | CIEM | Not started |
| 11 | Vulnerability prioritisation (CVSS + EPSS + KEV + exposure) | Not started |
| 12 | KSPM | Not started |
| 13 | Container registry and image scanning (+ container/serverless CWPP) | Not started |
| 14 | Code-to-cloud | Not started |
| 15 | Audit-log detection | Not started |
| 16 | DSPM | Not started |
| 17 | AI-SPM | Not started |
| 18 | API security posture | Not started |
| 19 | Remediation | Not started |
| 20 | More SSPM: GitHub, Okta, Slack, Salesforce | Not started |
| 21 | Natural-language graph search | Not started |
| 22 | Platform: MSP tenants, public API + webhooks, dashboards | Not started |

## Every phase (cross-cutting Definition of Done)

- [ ] Plan + ADR(s) approved by the owner before code. Phases 8, 10+ and anything that needs
      more than read-only access always get an ADR.
- [ ] Threat model updated: new rows at the start, statuses moved at the end.
- [ ] `security-reviewer` agent run on connectors, auth, tenancy, crypto, IaC and CI changes,
      with findings fixed.
- [ ] Tests (every check has pass and fail fixtures, negative tests for security code), coverage
      gates met, lint/types/CI green with zero warnings.
- [ ] Vendor details verified against official docs and cited (URL in code or metadata).
- [ ] No real cloud/SaaS calls, `git push` or `terraform apply` without the owner's approval.
- [ ] Docs updated (ARCHITECTURE, ROADMAP status, CLAUDE.md commands). Phase tagged
      `phase-N-start` / reviewed against it.

---

## Phase 0: Foundations

Status: **Done** (2026-11-24). Every slice was reviewed by the `security-reviewer` agent and
its findings fixed (docs/reviews/). The Definition of Done ran end to end on the Compose stack
(`deploy/compose/smoke_test.py`). The CI workflows are written but have not run on GitHub yet
(nothing pushed); their checks all passed locally: lint, types, tests with coverage gates,
pip-audit, both licence gates, gitleaks (history), semgrep, Trivy (images and config) and the
web build. CodeQL and Scorecard only run on GitHub.

Acceptance criteria:
- [x] Machine toolchain verified: git, gh, Docker engine, uv, Node LTS, pnpm, pre-commit.
- [x] `docs/ARCHITECTURE.md`, `docs/adr/0001–0012`, `docs/THREAT_MODEL.md` and
      `docs/ROADMAP.md` written.
- [x] Owner approves the design docs.
- [x] Monorepo scaffold (uv + pnpm workspaces), pre-commit (ruff, gitleaks, EOF, yaml…),
      `.editorconfig`, `.gitattributes`, README with a 5-minute quickstart, LICENSE
      (Apache-2.0), THIRD_PARTY.md, SECURITY.md, CONTRIBUTING.md, CODEOWNERS.
- [x] `packages/core`: settings, redaction logger, async DB, Alembic initial schema, RLS + DB
      roles, audit log, local KeyProvider + envelope encryption.
- [x] `packages/connectors`: protocol, `ApiGateway`, allowlist + a test failing on undeclared
      calls, deterministic `fake` connector.
- [x] `packages/checks`: schema, loader, engine; 5 checks with pass/fail fixtures.
- [x] `packages/frameworks`: catalogue format; Cyber Essentials v3.3 + ISO 27001:2022 stub
      mappings (`reviewed: false`).
- [x] `apps/worker`: scheduler + job runner; collect → evaluate → upsert; lifecycle new /
      still_open / auto_resolved / reopened.
- [x] `apps/api`:
  - [x] health/readiness, bootstrap admin, opaque sessions (SameSite=Lax + CSRF), RBAC
  - [x] integrations, scans, assets, findings filters, exceptions, audit log
- [x] `apps/web`: login, dashboard, findings table + drawer, assets, integrations.
- [x] `deploy/compose`: postgres, migrate, api, worker, web. Non-root, read-only FS,
      healthchecks.
- [x] CI:
  - [x] lint, types, tests + coverage, gitleaks, bandit (ruff S rules), semgrep, CodeQL, pip-audit, pnpm audit,
        licence gate, Docker build + Trivy, SBOM, e2e
  - [x] Dependabot, Scorecard; actions SHA-pinned
- [x] **DoD:**
  - [x] `docker compose up --build` from a clean clone → log in → scan the fake connector → 5
        findings with Cyber Essentials / ISO mappings
  - [x] "fix" a fake resource → rescan → auto-resolved
  - [x] a deep link from another site opens logged in
  - [x] all tests and CI checks pass locally; no secrets; no real cloud calls

Carried into Phase 1: the entry gate above Phase 1's criteria (per-scope persistence,
evaluation off the event loop, orphan-run sweep, vanished-scope policy), known-device login
bypass (THREAT_MODEL R9), a scan cooldown per integration, and running the Playwright browser
spec in CI.

## Phase 1: AWS connector, onboarding, CIS AWS checks

Status: Not started. ADR-0011 holds the onboarding design.

Entry gate (from the Phase 0 worker re-review), before the first real collector ships:
- [ ] Persist results per scope (not one final transaction per scan) and move check
      evaluation off the event loop (`asyncio.to_thread` or chunked with `sleep(0)`).
- [ ] A cross-tenant sweep for scan runs left active without a live job, plus a partial index
      on `jobs (kind, status, finished_at)` for the sweeper.
- [ ] Policy for assets in scopes that disappear from discovery (today they are kept).

Acceptance criteria:
- [ ] Single-source policy (`deploy/onboarding/aws/policy/`) renders:
  - [ ] the CloudFormation single-account template
  - [ ] the management-account + StackSet templates
  - [ ] the Terraform module (`deploy/terraform/onboarding/aws/`)
  - [ ] the UI permissions preview
  CI fails on drift. cfn-lint + checkov/Trivy clean.
- [ ] Managed policies verified (`SecurityAudit`/`ViewOnlyAccess` vs a custom read-only
      policy), with explicit data-plane denies, trust to the specific worker role ARN +
      `sts:ExternalId`, path `/skyline/`, version tag.
- [ ] **Connect AWS** opens a quick-create Launch Stack URL with pre-filled params. The
      registration Lambda calls back and the UI flips to "Connected — first scan running" with
      no copy-paste.
- [ ] Callback endpoint:
  - [ ] single-use token, ≤ 60 min TTL, bound to tenant+integration, atomic consume
  - [ ] strict schema, ARN validation, rate limits, generic responses, audit
  - [ ] negative tests for replay, expiry, wrong tenant, malformed ARN, oversized body, timing
- [ ] The worker verifies with AssumeRole + ExternalId before `connected`. The callback alone
      never connects. Paste-ARN fallback works through the same verification.
- [ ] StackSets org flow: member discovery via Organizations, "role missing" states, management
      account covered.
- [ ] Template versioning: immutable versions, SHA-256 in the UI, outdated-stack detection and
      an update link.
- [ ] Credential flow: AssumeRole per integration, local-dev profile mode (sandbox only), region
      discovery, pagination, jittered backoff, per-region failure isolation; boto3 `before-call`
      allowlist hook.
- [ ] Collectors: IAM, S3, EC2/VPC, RDS, CloudTrail, Config, GuardDuty, KMS, Lambda, EKS,
      normalised, with redaction (user data, Lambda env vars) and `api_allowlist` declared.
- [ ] 30 checks aligned to the current CIS AWS Foundations Benchmark (version verified), with
      moto pass/fail fixtures and our own wording.
- [ ] Relationships: instance→SG, instance→role, role→policy, bucket→policy.
- [ ] Performance: a 1,000-resource account (synthetic) in under 10 minutes.
- [ ] Manual sandbox end-to-end onboarding test, **run only with the owner's approval**.

## Phase 2: Microsoft 365 / Entra ID / Exchange Online

Status: Not started.

- [ ] Multi-tenant Entra app: one admin-consent link (`state` bound to the session). A guided
      script for self-hosters registering their own app. App-only permissions verified as least
      privilege.
- [ ] Client-assertion signing key held in KMS / Key Vault (sign-only, non-exportable).
- [ ] Graph collectors: users, auth methods, Conditional Access, roles + PIM, apps + grants,
      domains, org settings, Secure Score, SharePoint settings. Paging and Retry-After handled;
      licence-dependent checks return `not_applicable`.
- [ ] Exchange Online PowerShell collector container (app-only cert), or a stub + ADR, with the
      checks that need it listed.
- [ ] 25 checks (CISA SCuBA M365 + CIS M365 informed) + SPF/DKIM/DMARC via DNS. Recorded
      fixtures. CE + ISO mappings.

## Phase 3: Google Workspace

Status: Not started.

- [ ] DWD onboarding wizard: copy buttons, exact `*.readonly` scopes (verified, incl. the Cloud
      Identity Policy API), minimal custom admin role, prominent DWD warning, test connection.
      Investigate a Marketplace app.
- [ ] Collectors: users / 2SV / admins / last login, roles, OUs, domains, Policy API settings,
      OAuth token usage, Alert Center.
- [ ] 20 checks (CISA SCuBA GWS + CIS GWS informed) + SPF/DKIM/DMARC. Recorded fixtures.

## Phase 4: Deploy anywhere, incl. Skyline-on-AWS reference

Status: Not started. ADR-0012 holds the reference design.

- [ ] Hardened images (non-root, read-only FS, minimal, healthchecks), SBOMs, cosign keyless
      signing, GHCR publish on tags.
- [ ] Helm chart: external Postgres, existing Secret / CSI, ingress path routing, worker HPA,
      NetworkPolicies, PSS restricted, workload identity per SA, migrate hook. `helm lint` +
      kind smoke test in CI.
- [ ] Single VM: Compose + Caddy (auto TLS), encrypted Postgres backup script.
- [ ] **4a: Terraform `deploy/terraform/hosting/aws`.**
  - [ ] VPC with private subnets + VPC endpoints, ECS Fargate web/api/worker + migrate task
  - [ ] RDS PostgreSQL 17 (CMK, TLS, Multi-AZ option, backups, deletion protection)
  - [ ] KMS CMKs (api encrypt-only, worker decrypt-only), Secrets Manager
  - [ ] ALB + ACM + WAF (rate rules on login and callback)
  - [ ] CloudWatch logs and alarms, templates bucket, GitHub OIDC roles, S3 state backend
- [ ] **4b: CloudFormation equivalent** with a resource-parity checklist test against 4a.
- [ ] Documented upgrade path: semver, expand/contract migrations, pre-upgrade RDS snapshot,
      rollback procedure. Sizing profiles and cost notes.
- [ ] Cross-cloud identity to AWS: `AssumeRoleWithWebIdentity` from Azure managed identity / GCP
      SA; IAM Roles Anywhere for on-prem.
- [ ] `deploy/terraform/hosting/{azure,gcp}` equivalents.
- [ ] KeyProvider implementations for AWS KMS, Azure Key Vault and GCP KMS, with
      encryption-context tests.
- [ ] `docs/DEPLOYMENT.md` with a path for each target. **Plan only: nothing applied without
      approval.**

## Phase 5: Compliance and reporting

Status: Not started.

- [ ] Catalogues: ISO/IEC 27001:2022 Annex A, Cyber Essentials (current version, verified), CIS
      per provider, NIST CSF 2.0. Control IDs + our own wording only.
- [ ] Mapping review workflow (admin approves; `reviewed` with reviewer and time).
- [ ] Compliance dashboard per framework (pass / fail / N-A per control, trend).
- [ ] Evidence exports: CSV (formula-injection safe), JSON, PDF, with scan timestamps and scope.
- [ ] Exceptions shown against controls with expiry and approver. Request/approve (four-eyes)
      workflow.

## Phase 6: Azure and GCP connectors

Status: Not started.

- [ ] Azure:
  - [ ] Deploy-to-Azure / Cloud Shell onboarding at management-group scope (Reader + Security
        Reader), cert/WIF credentials
  - [ ] Resource Graph inventory; 20 CIS-aligned checks; relationships; fixtures
- [ ] GCP:
  - [ ] Cloud Shell / Terraform onboarding with WIF (`roles/viewer` +
        `roles/iam.securityReviewer` at org/folder)
  - [ ] Cloud Asset Inventory; 20 CIS-aligned checks; relationships; fixtures

## Phase 7: Security graph and risk prioritisation

Status: Not started.

- [ ] Graph query layer (recursive CTEs, depth caps) + path-query API.
- [ ] Effective exposure (public IP + SG/NSG/firewall + LB), identity reach, sensitivity from
      tags.
- [ ] Risk score per finding (brief §6). 5 toxic-combination rules as first-class "issues".
- [ ] Issue view with an attack-path visual and a "fix this first" list.
- [ ] 50k-asset benchmark + ADR on the need for a graph DB.

## Phase 8: Agentless workload scanning (snapshot-based, VMs)

Status: Not started. Plan + ADR before any code, because this changes the permission model.

- [ ] Snapshot → share to scanner account → mount read-only (or EBS direct APIs) → SBOM + vuln +
      secrets + EOL software → guaranteed cleanup with alarms. Scanner licences confirmed.
- [ ] Opt-in add-on onboarding stack, separate from the base role. KMS-encrypted snapshot
      handling, cost controls, concurrency limits.
- [ ] Vulnerable-package findings linked into the graph (feeds Phase 7 and 11).

## Phase 9: SaaS mode, SSO, integrations, scheduled scans and diffing

Status: Not started.

- [ ] OIDC SSO (Entra ID, Google), optional SCIM, RBAC roles finalised, API tokens.
- [ ] Multi-tenant mode: tenant signup/admin, per-tenant KMS data keys, per-tenant rate limits
      and scan quotas, tenant-isolation suite in CI, platform-operator roles with break-glass
      audit.
- [ ] Notifications: Slack, Teams, email, Jira (create/sync), generic webhooks, all behind the
      SSRF guard. Notification rules. Deep links open logged in.
- [ ] Scheduled scans per integration. Asset history (`asset_versions`) and "what changed since
      yesterday" diffing (CSPM drift).
- [ ] Audit-log hash chain.

## Phases 10+: feature parity (brief §11)

Each phase uses the template in `prompts/01-PHASE-PROMPTS.md`: plan + ADR covering:
- the permissions it needs
- an opt-in stack, if it needs more than read-only access
- the data it stores
- the cost impact
- threat-model updates

The owner approves before any build. Order follows the suggested sequence and may change via ADR.

### Phase 10: CIEM
- [ ] Effective-permissions engine (identity and resource policies, SCPs, permission boundaries,
      session policies) for AWS first, then Azure and GCP.
- [ ] Unused/excessive permission findings (from access-advisor / last-used data, read-only).
- [ ] Privilege-escalation path rules. Cross-account trust analysis.
- [ ] Least-privilege policy suggestions (generated, never applied).
- [ ] Graph edges for "can access" feeding Phase 7 attack paths.

### Phase 11: Vulnerability prioritisation
- [ ] Ingest CVSS, **EPSS** and **CISA KEV** (scheduled, cached, licence-checked).
- [ ] Combine them with exposure and reachability from the graph into a prioritised
      vulnerability view.
- [ ] Applies to Phase 8 VM findings now and Phase 13 image findings later.

### Phase 12: KSPM
- [ ] EKS/AKS/GKE cluster posture (control plane config, logging, endpoint exposure) via cloud
      APIs.
- [ ] In-cluster read-only access (opt-in, ADR): workloads, RBAC, network policies, admission
      policies. CIS Kubernetes-aligned checks.
- [ ] Kubernetes objects in the graph.

### Phase 13: Container registry and image scanning (+ container/serverless CWPP)
- [ ] ECR/ACR/GAR/Docker Hub inventory and image scanning (SBOM, vulns, secrets, EOL) with
      read-only registry access.
- [ ] Running-container and serverless package scanning linked to workloads.
- [ ] Image → workload edges in the graph.

### Phase 14: Code-to-cloud
- [ ] IaC scanning (Terraform, CloudFormation, Helm) as a CI action/CLI.
- [ ] Secrets-in-repo scanning.
- [ ] CI/CD posture for GitHub/GitLab (branch protection, actions pinning, OIDC trust).
- [ ] Trace a cloud finding back to the IaC resource / commit that created it (tags + state
      mapping).

### Phase 15: Detection (audit-log based)
- [ ] Ingest CloudTrail, Entra sign-in/audit and Workspace audit logs (read-only, bounded
      volume).
- [ ] Small detection rule set (e.g. root login, MFA disabled, new admin, unusual AssumeRole)
      with alerts.
- [ ] Optional lightweight runtime sensor: **ADR first**; not built by default.

### Phase 16: DSPM
- [ ] Data store discovery (S3, RDS, Blob, GCS, BigQuery…).
- [ ] Sensitive-data classification by sampling. **Opt-in, separate data-read stack** (ADR), with
      in-account processing preferred and no raw data leaving the customer by default.
- [ ] Sensitivity labels feed risk scoring.

### Phase 17: AI-SPM
- [ ] Inventory and posture of AI services (Bedrock, Azure OpenAI, Vertex AI): models,
      endpoints, guardrails, logging, network exposure, data access.
- [ ] AI resources in the graph and AI-specific checks.

### Phase 18: API security posture
- [ ] Discover exposed API gateways/endpoints (API Gateway, APIM, Apigee, ALB/Ingress routes)
      and their auth configuration.
- [ ] Checks for unauthenticated or overly permissive APIs. Internet-exposure correlation.

### Phase 19: Remediation
- [ ] Step-by-step guidance (already in check metadata from Phase 1) surfaced per finding.
- [ ] Generated Terraform/CLI fix snippets (never executed by Skyline).
- [ ] Two-way ticket sync (Jira and others) building on Phase 9.
- [ ] **Optional opt-in auto-remediation only via ADR + a separate permission stack + a separate
      identity.** The base role stays read-only.

### Phase 20: More SSPM
- [ ] Connectors for GitHub, Okta, Slack and Salesforce. Each gets one-click onboarding,
      read-only scopes and baseline checks.

### Phase 21: Natural-language graph search
- [ ] Natural-language questions translated into graph queries.
- [ ] **Pushback / constraint:** no customer data goes to third-party LLM services
      (`SECURE_CODING.md`). Either schema-only translation, where the model sees the graph schema
      and the question but never results, or a self-hosted model. Opt-in per tenant. ADR
      required.

### Phase 22: Platform
- [ ] MSP / parent-child tenants with explicit, audited delegation.
- [ ] Public versioned API + outbound webhooks (SSRF-guarded), API tokens with scopes.
- [ ] Customisable dashboards and scheduled reports.

---

## §11 coverage matrix (nothing dropped)

| Brief §11 item | Phases |
|---|---|
| CSPM: multi-cloud misconfiguration, frameworks, drift/history | 1, 6 (connectors), 5 (frameworks), 9 (drift/history) |
| SSPM: M365/Entra/Exchange, Google Workspace; later Slack, GitHub, Okta, Salesforce | 2, 3, 20 |
| Security graph & attack paths: toxic combinations, blast radius, risk prioritisation | 7 (+ 10 identity paths) |
| Agentless workload scanning (CWPP): vulns, malware, secrets, EOL, VMs/containers/serverless, SBOM | 8 (VMs), 13 (containers, serverless) |
| CIEM: effective/unused permissions, privilege escalation, cross-account trust, least-privilege suggestions | 10 |
| DSPM: data discovery, sensitive-data classification (opt-in sampling) | 16 |
| KSPM: EKS/AKS/GKE posture, workloads, RBAC, admission | 12 |
| Container registry & image scanning: ECR/ACR/GAR/Docker Hub | 13 |
| Code-to-cloud: IaC, repo secrets, CI/CD posture, cloud→code tracing | 14 |
| Vulnerability prioritisation: CVSS + EPSS + KEV + reachability | 11 |
| AI-SPM: Bedrock, Azure OpenAI, Vertex AI | 17 |
| API security posture | 18 |
| Detection: audit-log threat detection; optional runtime sensor (ADR) | 15 |
| Remediation: guidance, generated fixes, ticket sync, opt-in auto-remediation (ADR) | 19 (guidance from 1, tickets from 9) |
| Platform: NL search, dashboards, reports, RBAC/SSO/SCIM, multi-tenant SaaS, MSP, public API + webhooks | 9 (SSO/SCIM/SaaS), 5 (reports), 21 (NL search), 22 (MSP, API, webhooks, dashboards) |
