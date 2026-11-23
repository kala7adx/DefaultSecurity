# Phase prompts — one per Claude Code session

How to use: start a fresh session (`/clear`), switch to Plan mode (Shift+Tab), paste the phase
prompt. Approve the plan, then let it build. Commit and review before moving on.
Every prompt assumes Claude has read `CLAUDE.md`, `docs/PRODUCT_BRIEF.md`, `docs/ARCHITECTURE.md`
and `docs/ROADMAP.md` — the first line tells it to.

---

## Phase 1 — AWS connector + CIS checks

Read CLAUDE.md, docs/PRODUCT_BRIEF.md, docs/ARCHITECTURE.md and docs/ROADMAP.md first.
Implement Phase 1: the AWS connector.
1. Onboarding artefacts in `deploy/terraform/onboarding/aws/` (Terraform module) and a matching
   CloudFormation template: read-only role trusted by the Skyline principal with an ExternalId
   condition. Verify current AWS managed policy names and whether a tighter custom policy is better.
2. Credential flow: AssumeRole with per-integration ExternalId; local-dev profile mode.
   Region discovery; pagination; jittered backoff on throttling; per-region failure isolation.
3. Collectors for the services listed in the brief, normalised to Asset/Relationship records,
   with secret-bearing fields redacted (EC2 user data, Lambda env vars). Declare the api_allowlist.
4. 30 checks aligned to the current CIS AWS Foundations Benchmark (verify version; reference
   control IDs, write descriptions in our own words), each with pass/fail fixtures using moto.
5. Relationships: instance→SG, instance→role, role→policy, bucket→policy, so the graph phase has data.
6. UI: integration wizard for AWS (shows the Terraform/CFN, collects role ARN, tests connection).
Ask before anything touches a real AWS account. Then I will run it against my sandbox account.

---

## Phase 2 — Microsoft 365 / Entra ID / Exchange Online (SSPM)

Read the docs first. Implement the M365 connector.
1. Onboarding guide + script (PowerShell or Terraform azuread provider) creating an app
   registration with application permissions only, certificate credential, admin consent.
   Verify each Graph permission is the least-privilege read permission for the data we need.
2. Collectors via Microsoft Graph (users, auth methods registration, Conditional Access policies,
   directory roles and PIM assignments, apps and OAuth grants, domains, org settings, Secure Score,
   SharePoint tenant settings). Handle paging, throttling (Retry-After), and licence-dependent
   endpoints gracefully (mark checks "not applicable", not "failed").
3. Identify checks needing Exchange Online PowerShell (e.g. transport rules, SMTP AUTH, remote
   domain forwarding). Design a separate PowerShell collector container with app-only cert auth;
   implement it if straightforward, otherwise stub with a clear TODO and an ADR.
4. 25 checks informed by CISA SCuBA M365 baselines and the CIS M365 benchmark, plus DNS-based
   SPF/DKIM/DMARC checks. Recorded-fixture tests only.
5. Framework mappings to Cyber Essentials (user access control, secure configuration) and ISO 27001.

---

## Phase 3 — Google Workspace (SSPM)

Read the docs first. Implement the Google Workspace connector.
1. Onboarding guide: GCP project, service account, domain-wide delegation with read-only scopes
   only, impersonated admin with a minimal custom role. Verify every scope against current docs,
   including the Cloud Identity Policy API for reading admin settings.
2. Collectors: users (2SV enrolment/enforcement, admin status, last login), admin roles and
   assignments, org units, domains, settings via the Policy API, OAuth token/app usage from Reports,
   Alert Center alerts.
3. 20 checks informed by CISA SCuBA Google Workspace baselines and the CIS Google Workspace
   benchmark, plus SPF/DKIM/DMARC. Recorded-fixture tests.
4. UI: integration wizard with a clear warning explaining DWD and how we scope it.

---

## Phase 4 — Deploy anywhere

Read the docs first. Make Skyline deployable on any cloud.
1. Harden images (non-root, read-only FS, minimal base, healthchecks), produce SBOMs, sign images
   (cosign) and publish to GHCR from CI on tags.
2. Helm chart in `deploy/helm/skyline` (external Postgres support, secrets via existing Secret or
   CSI driver, ingress, HPA for workers, NetworkPolicies, PodSecurity restricted). `helm lint` +
   `kind`-based smoke test in CI.
3. Single-VM deploy: Compose + Caddy (auto TLS), backup script for Postgres.
4. Terraform hosting modules: `deploy/terraform/hosting/{aws,azure,gcp}` (managed Postgres, KMS /
   Key Vault, container platform or managed K8s, secrets store, private networking). Implement the
   KeyProvider for each KMS. Plan only — never apply without my approval.
5. `docs/DEPLOYMENT.md` with a path for each target.

---

## Phase 5 — Compliance and reporting

Read the docs first. Build compliance views.
1. Framework catalogues for ISO/IEC 27001:2022 Annex A, Cyber Essentials (current requirements
   version — verify), CIS (per provider), NIST CSF 2.0. Control IDs and our own short descriptions
   only — no copyrighted text.
2. Mapping review workflow: mappings start `reviewed: false`; an admin approves them in the UI.
3. Compliance dashboard per framework (pass/fail/not-applicable per control, trend over time).
4. Evidence exports: CSV, JSON and PDF report for auditors, with scan timestamps and integration scope.
5. Exceptions/accepted risks shown against controls with expiry and approver.

---

## Phase 6 — Azure and GCP connectors

Read the docs first. Implement Azure (Resource Graph for inventory, Reader + Security Reader at
management-group scope) and GCP (Cloud Asset Inventory, WIF preferred) connectors with onboarding
artefacts, 20 CIS-aligned checks each, relationships for the graph, and fixture tests.

---

## Phase 7 — Security graph and risk prioritisation

Read the docs first.
1. Graph query layer over nodes/edges (recursive CTEs), with an API for path queries.
2. Effective-exposure computation: internet reachability (public IP + SG/NSG/firewall rules +
   load balancers), identity reach (role → permissions → resources), sensitivity from tags.
3. Risk score per finding per the brief; 5 toxic-combination rules as first-class "issues"
   that group the underlying findings.
4. UI: issue view with an attack-path visual (e.g. React Flow), and "fix this first" list.
5. Benchmark query performance on a synthetic 50k-asset tenant; write an ADR on whether a
   dedicated graph DB is needed.

---

## Phase 8 — Agentless workload scanning (snapshot-based)

Read the docs first. Write the plan and ADR before any code; this phase changes the permission model.
1. Design: snapshot EBS volumes (later Azure/GCP disks), share to a scanner account, create volume,
   attach to an ephemeral scanner instance or use EBS direct APIs, mount read-only, run SBOM +
   vuln scanning (Trivy/Grype/Syft — confirm licences), secret scanning, then clean up.
   Cost controls, concurrency limits, KMS-encrypted snapshot handling, and guaranteed cleanup.
2. The extra permissions are **opt-in**, in a separate onboarding module, clearly documented.
3. Findings: vulnerable packages per workload, linked into the graph (feeds Phase 7 risk).

---

## Phase 9 — SaaS mode, SSO and integrations

Read the docs first.
1. OIDC SSO (Entra ID, Google), SCIM provisioning optional, RBAC roles finalised.
2. Multi-tenant mode: tenant signup/admin, per-tenant KMS data keys, per-tenant rate limits,
   tenant-isolation test suite in CI.
3. Integrations: Slack, Microsoft Teams, email, Jira (create/sync tickets), generic webhooks,
   with notification rules (e.g. new critical issue in prod).
4. Scheduled scans per integration; scan history and diffing ("what changed since yesterday").

---

## Useful one-off prompts

- **Security review of a phase:** "Use the security-reviewer agent to review everything changed
  since tag `phase-N-start`. Report findings by severity with file/line and a fix."
- **Add a check:** "Add a check that <condition> for <provider/resource>. Follow the check schema,
  add pass/fail fixtures, map to Cyber Essentials and ISO 27001 (reviewed: false), run tests."
- **Refresh docs:** "Update ARCHITECTURE.md, ROADMAP.md and CLAUDE.md commands to match the code
  as it is now. Keep CLAUDE.md under 120 lines."
