# Skyline — Product Brief

This is the founding brief for the platform. Claude Code: treat this as the product owner's intent.
Where it is ambiguous, ask. Where a vendor API detail is stated here, verify it against current docs.

---

## 1. Vision

Give a security team one place to answer three questions across clouds and SaaS:

1. **What do we have?** — a live, normalised inventory of assets and identities.
2. **What is wrong with it?** — misconfigurations, risky identities, exposures, vulnerabilities.
3. **What should we fix first?** — findings prioritised by real risk (exposure × privilege ×
   sensitivity × exploitability), not by a flat severity list — and mapped to the compliance
   frameworks we are audited against.

## 2. How the category leaders did it (and what we copy conceptually, not literally)

- **Agentless by design.** Wiz and Orca won by not asking customers to install agents. They connect
  through the provider's own APIs using a read-only role the customer creates in minutes
  (AWS cross-account role, Azure app registration / Lighthouse, GCP service account / WIF).
- **Snapshot-based workload scanning** (Orca calls it SideScanning). Instead of agents on VMs, the
  platform snapshots disks, mounts them in a scanner account, and inspects the filesystem for
  vulnerable packages, secrets and malware. This is a *later* phase for us.
- **The security graph** (Wiz's core idea). Assets, identities, network paths, data stores and
  vulnerabilities become nodes and edges, so you can ask questions like "internet-exposed VM with a
  critical CVE whose role can read a bucket tagged PII". These multi-factor combinations ("toxic
  combinations") are how they prioritise.
- **SaaS delivery.** They run multi-tenant SaaS; customers never host anything. We will be
  **self-hostable first** (any cloud, any Kubernetes, or one VM) and **multi-tenant ready**, so
  SaaS is a deployment choice later, not a rewrite.
- **SSPM** (SaaS posture) is the same idea applied to Microsoft 365 / Entra ID / Exchange Online
  and Google Workspace: read tenant settings via APIs, compare to secure baselines.

## 3. Scope

### In scope (MVP → v1)
- Connectors: AWS (first), Microsoft 365 + Entra ID + Exchange Online, Google Workspace,
  then Azure and GCP.
- Asset inventory with history (first_seen / last_seen / config change diff).
- Check engine with framework mappings: CIS benchmarks (AWS, Azure, GCP, M365, Google Workspace),
  ISO/IEC 27001:2022 Annex A, UK Cyber Essentials, NIST CSF 2.0; CISA SCuBA baselines for M365 and
  Google Workspace as a strong reference for SaaS checks.
- Findings lifecycle: open → muted/accepted-risk (with expiry + justification) → resolved
  (auto-resolve when a later scan passes) → reopened.
- Risk scoring and a basic asset graph with a handful of toxic-combination rules.
- Compliance views and evidence exports (CSV/JSON/PDF) for auditors.
- Notifications/integrations: email, Slack, Microsoft Teams, Jira, generic webhook.
- Auth: local accounts for bootstrap, then OIDC SSO (Entra ID, Google), RBAC (admin, analyst, viewer).
- Deploy: Docker Compose (single VM), Helm (EKS/AKS/GKE/any K8s), Terraform hosting modules.

### Later
- Agentless snapshot workload scanning (vulns via SBOM, secrets, malware).
- CIEM (effective permissions analysis), DSPM (data classification), KSPM (Kubernetes posture),
  IaC scanning in CI, container registry scanning.
- Auto-remediation (explicitly out of scope until an ADR approves it — read-only is a selling point).

### Out of scope
- Runtime agents/EDR, SIEM features, log ingestion at scale.

## 4. Architecture (target)

```
            ┌──────────── Web UI (Next.js) ───────────┐
            │                                          │
            ▼                                          │
     API service (FastAPI) ── auth/RBAC/tenancy ───────┘
            │
            ├── PostgreSQL (assets JSONB, graph nodes/edges, findings, audit log, RLS per tenant)
            │
     Scheduler ──► Job queue ──► Workers
                                  ├─ Connector runners (collect → normalise → upsert assets/edges)
                                  ├─ Check engine (evaluate checks → findings)
                                  ├─ Risk scorer / graph rules
                                  └─ Notifiers / exporters
                                  │
                      KeyProvider (local | AWS KMS | Azure Key Vault | GCP KMS)
```

### Key design principles
- **Connector plugin interface.** Each provider implements: `validate_credentials()`,
  `discover_scopes()` (accounts/regions/OUs/subscriptions/projects), `collect(scope)` yielding
  normalised `Asset` and `Relationship` records, and a declared `api_allowlist`.
  A `fake` connector with deterministic fixtures exists so the whole pipeline runs without any cloud.
- **Collect once, evaluate many.** Collection stores raw (redacted) config; checks evaluate against
  stored data, so new checks can run without re-collecting.
- **Checks as data + code.** Each check has YAML metadata (id, title, description, severity, provider,
  resource types, rationale, remediation steps, references, framework mappings) and a small,
  pure Python evaluator `evaluate(asset, context) -> Result(status, evidence)`. Keep an interface so
  Rego/CEL policies or graph queries can be added as other evaluator types.
- **Idempotent, resumable scans** with per-scope concurrency limits, API throttling/backoff, and
  partial-failure reporting (a failed region must not fail the scan).
- **Graph in Postgres first** (nodes/edges tables + recursive CTEs). Revisit a dedicated graph DB
  via ADR only when query needs prove it.
- **12-factor config**, everything via env vars; no cloud-specific services required to run.

### Core data model (initial)
`Tenant`, `User`, `Role`, `Integration` (a connected cloud account / SaaS tenant, with encrypted
credential reference), `ScanRun`, `Asset` (provider, type, native_id/ARN, region, account, name,
tags, raw_config JSONB redacted, config_hash, first_seen, last_seen, deleted_at), `Relationship`
(src, dst, type), `Check`, `Framework`, `Control`, `CheckControlMap`, `Finding` (asset, check,
status, severity, risk_score, evidence JSONB, first_seen, last_seen, resolved_at, state),
`Exception` (scope, justification, approver, expires_at), `AuditLog`, `NotificationRule`.

## 5. Connector notes (verify every permission/scope against current docs before coding)

### AWS (first)
- Customer onboarding: CloudFormation template **and** Terraform module creating an IAM role trusted
  by the Skyline platform principal with `sts:ExternalId` condition; attach AWS managed
  `SecurityAudit` + `ViewOnlyAccess` (or a tighter custom policy). Org-wide via StackSets later.
- Local dev: allow an AWS CLI profile pointing at a **dedicated sandbox account**.
- Initial services: IAM (credential report, password policy, root MFA, access key age, unused
  credentials), S3 (public access block, bucket policy/ACL exposure, encryption, versioning),
  EC2 (instances, public IPs, IMDSv2, EBS encryption, security groups open to 0.0.0.0/0 on admin
  ports), VPC (flow logs, default SG), RDS (public, encryption, backups), CloudTrail (multi-region,
  log file validation), AWS Config, GuardDuty enabled, KMS rotation, Lambda (public URLs,
  deprecated runtimes), EKS (public endpoint, logging).
- Enumerate enabled regions; paginate everything; handle throttling with jittered backoff.
- Map to the current CIS AWS Foundations Benchmark version (verify the version number).

### Microsoft 365 / Entra ID / Exchange Online ("Outlook")
- Onboarding: Entra app registration, **application** permissions, admin consent, certificate
  credential. Likely Graph permissions (verify): `Directory.Read.All`, `Policy.Read.All`,
  `RoleManagement.Read.Directory`, `AuditLog.Read.All`, `Reports.Read.All`,
  `UserAuthenticationMethod.Read.All`, `Application.Read.All`, `Domain.Read.All`,
  `SecurityEvents.Read.All`, `SharePointTenantSettings.Read.All`, `Organization.Read.All`.
- Some Exchange Online / Purview settings are not exposed in Graph and need Exchange Online
  PowerShell (app-only, certificate) — design the connector so a PowerShell-based collector
  container can be added. Document which checks need it.
- Example checks: legacy authentication blocked; MFA required for all users and admins
  (Conditional Access or security defaults); phishing-resistant MFA for admins; 2–4 Global Admins;
  privileged roles not permanently assigned (PIM); user consent to apps restricted; risky OAuth
  app grants; guest access restricted; external sharing in SharePoint/OneDrive limited;
  external auto-forwarding blocked; SMTP AUTH disabled; DKIM enabled; SPF/DMARC published
  (DNS lookups); unified audit log enabled; Secure Score ingestion.
- Reference: CISA SCuBA M365 baselines (ScubaGear), CIS Microsoft 365 Foundations Benchmark.

### Google Workspace
- Onboarding: GCP project + service account with **domain-wide delegation**, read-only scopes only,
  impersonating a dedicated admin with a minimal custom admin role. Likely scopes (verify):
  `admin.directory.user.readonly`, `admin.directory.domain.readonly`,
  `admin.directory.rolemanagement.readonly`, `admin.directory.orgunit.readonly`,
  `admin.reports.audit.readonly`, `cloud-identity.policies.readonly` (Policy API for settings),
  and Alert Center read access.
- Example checks: 2-Step Verification enforced (and security keys for admins); super-admin count;
  external Drive sharing settings; Gmail external auto-forwarding; DKIM/SPF/DMARC; third-party
  OAuth app access controls; password policy; login challenges; inactive accounts.
- Reference: CISA SCuBA Google Workspace baselines (ScubaGoggles), CIS Google Workspace Benchmark.
- Call out clearly in the UI that DWD is powerful and how to scope it.

### Azure and GCP (after the SaaS connectors)
- Azure: app registration with `Reader` + `Security Reader` at management-group scope; Resource
  Graph for fast inventory. GCP: WIF or service account with `roles/viewer` +
  `roles/iam.securityReviewer` at org/folder; Cloud Asset Inventory API for inventory.

## 6. Risk prioritisation (v1 heuristic, refine later)
`risk = severity_weight × exposure (internet-facing?) × privilege (admin/role reach) ×
sensitivity (data tags, prod tags) × exploitability (known-exploited CVE, later)`.
Start with ~5 toxic-combination graph rules, e.g. public EC2 + SG open on 22/3389 + instance role
with admin-equivalent permissions; public S3 bucket tagged sensitive; Global Admin without MFA.

## 7. Compliance
- Frameworks are catalogues of controls; checks map many-to-many to controls.
- Priority for the owner: **ISO/IEC 27001:2022 Annex A** and **UK Cyber Essentials**
  (firewalls, secure configuration, security update management, user access control, malware
  protection — verify the current requirements document version). Then CIS, NIST CSF 2.0, SOC 2.
- Draft mappings may be generated, but every mapping is marked `reviewed: false` until a human
  approves it. Never reproduce copyrighted benchmark text verbatim — reference control IDs and
  write descriptions in our own words.

## 8. Security of Skyline itself
Skyline is a high-value target: it holds read access to every customer environment.
- Threat model (STRIDE) maintained in `docs/THREAT_MODEL.md` and updated each phase.
- Separate the collector identity from the API identity; workers hold credentials only in memory
  for the duration of a job.
- Signed container images, SBOMs, pinned base images, non-root containers, read-only root FS.
- Rate-limited, authenticated API; CSRF protection; strict CSP in the web app.
- Backups encrypted; documented key rotation.

## 9. Deployment targets
1. Local: Docker Compose (`docker compose up` gives api, worker, web, postgres).
2. Single VM on any cloud: same Compose file + reverse proxy (Caddy) with TLS.
3. Kubernetes: Helm chart (values for EKS / AKS / GKE / generic), external Postgres supported.
4. Terraform hosting modules per cloud (managed Postgres, KMS, container platform, secrets store).
5. Later SaaS: same images, multi-tenant mode on, per-tenant KMS keys.

## 10. Non-functional targets (initial)
- Scan of a 1,000-resource AWS account in < 10 minutes.
- New check added without code changes outside `packages/checks/`.
- All connectors testable offline with fixtures; CI never calls real cloud APIs.
