# 0012. Skyline on AWS: reference deployment

- Status: Proposed (design in Phase 0; implementation in Phase 4: Terraform 4a, CloudFormation 4b)
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Brief §9: the owner's production runs on AWS, and the AWS hosting module is the reference.
It needs:
- one CloudFormation template **and** one Terraform module
- a VPC with private subnets
- ECS on Fargate (or EKS via Helm)
- RDS PostgreSQL (encrypted, Multi-AZ option, automated backups)
- KMS for envelope encryption, Secrets Manager
- ALB + ACM + WAF, CloudWatch
- least-privilege task roles: API encrypt-only; worker decrypt-only + `sts:AssumeRole` into
  customer roles
- an upgrade path

The platform's AWS account is the principal that customer onboarding roles trust. Azure and GCP
hosting must keep working from the same images and chart.

## Decision

### Topology
- **VPC:** 2–3 AZs. The ALB sits in public subnets; ECS tasks and RDS in private subnets. A NAT
  gateway handles SaaS egress (Graph, Google). **VPC endpoints** for STS, KMS, Secrets Manager,
  ECR (api + dkr), CloudWatch Logs and S3 (gateway) keep AWS API traffic private.
- **Compute:** ECS Fargate services `web`, `api` and `worker`, each with its own task role,
  security group and log group. `migrate` runs as a one-off task before each service update. The
  worker accepts no inbound connections. EKS + the Helm chart is the supported alternative.
- **Database:**
  - RDS PostgreSQL 17, encrypted with a CMK, `rds.force_ssl = 1`, Multi-AZ toggle, automated
    backups (encrypted), deletion protection, Performance Insights encrypted.
  - The master password is managed by RDS in Secrets Manager. Each app role (`skyline_owner`,
    `skyline_api`, `skyline_worker`) has its own secret.
- **Keys:**
  - KMS CMK `skyline-secrets` for envelope encryption, with a key policy granting the api role
    `GenerateDataKey`/`Encrypt` only and the worker role `Decrypt` only. Both are conditioned on
    the `tenant_id`/`purpose` encryption context keys.
  - Separate CMKs for RDS, logs and S3. Automatic rotation on for all.
- **Edge:**
  - ALB with an ACM certificate, HTTPS only (HTTP redirects), the current recommended TLS policy
    (name verified in Phase 4), and drop-invalid-header-fields on.
  - Path rules route `/api/*` → api and `/*` → web, keeping one origin (ADR-0008).
  - AWS WAF with managed rule groups (common, known bad inputs, IP reputation) plus rate-based
    rules on `/api/v1/auth/login` and `/api/v1/onboarding/*/register`.
  - Optionally, IP allowlist or VPN access for the UI, while the onboarding callback stays
    reachable.
  - ALB access logs go to an encrypted S3 bucket.
- **Observability:** CloudWatch log groups (KMS, set retention) and alarms for 5xx, unhealthy
  tasks, RDS CPU/storage/connections, queue depth (custom metric) and AssumeRole error rate.
  Dogfooding is optional: Skyline can scan its own platform account.
- **Templates bucket:** a dedicated S3 bucket holding only onboarding templates under
  `templates/`, with public read on that prefix (CloudFormation quick-create needs an S3
  `templateURL`), versioning and Object Lock in governance mode. Writes are limited to the
  release pipeline role. Skyline's own public-bucket check is intentionally muted there with a
  recorded exception.

### Identities (least privilege)
- **api task role:** `kms:GenerateDataKey`/`kms:Encrypt` on `skyline-secrets`, and
  `secretsmanager:GetSecretValue` on its own DB secret only.
- **worker task role:**
  - `kms:Decrypt` on `skyline-secrets`
  - `secretsmanager:GetSecretValue` on its own DB secret
  - `sts:AssumeRole` on `arn:aws:iam::*:role/skyline/*`. That's a **recorded exception** to "no
    wildcard resources": customer account IDs aren't known in advance. It is limited by the
    `/skyline/` path and by each customer role's trust policy requiring this exact principal and
    that integration's ExternalId.
- **web task role:** no permissions.
- **Execution role:** ECR pull from the Skyline repositories, log writes, and the specific secrets
  injected at start.
- **The worker role is the principal customers trust.** It must never be deleted and recreated,
  because trust policies bind to the role's unique ID. Protect it with an SCP or deny-delete
  guard, and alarm on unusual `AssumeRole` volume or failures in CloudTrail.

### Supply chain and state
- Images are built and signed (cosign keyless) in CI. The deploy pipeline **verifies signatures
  and SBOMs**, then mirrors them to ECR, and task definitions pin image digests.
- Terraform state lives in S3 (KMS-encrypted, versioned, lock file) in the platform account, with
  restricted access.
- CI deploy and template-publish access uses **GitHub OIDC** roles scoped to protected
  environments and specific repo refs. GitHub holds no AWS keys.

### Upgrade path
- Releases are semver, and the release notes list migration notes.
- Migrations follow **expand/contract**: release N's schema works with release N−1's code.
  `migrate` runs before services update. Destructive changes ship only in a later release.
- An RDS snapshot is taken before every upgrade. Rollback means the previous task definition,
  with no destructive migrations in between. ECS deployment circuit breaker on.

### Two IaC formats
- Both are delivered, as the brief asks. **Terraform first** (Phase 4a, under
  `deploy/terraform/hosting/aws`), then **CloudFormation** (Phase 4b, under
  `deploy/cloudformation/hosting/`).
- IAM policy documents come from one source (as in ADR-0011). A **resource-parity checklist
  test** compares the resource types and key properties of both. cfn-lint, checkov/Trivy and
  `terraform validate` run in CI.
- Neither is applied without the owner's explicit approval.

### Running Skyline outside AWS (cross-cloud identity)
- Customer AWS roles always trust the operator's **AWS** worker role. When Skyline runs on Azure
  or GCP, the worker obtains that role with `sts:AssumeRoleWithWebIdentity`, using its managed
  identity or service-account token through an IAM OIDC provider. On-prem VMs use **IAM Roles
  Anywhere**.
- It then chains into customer roles. Role chaining caps sessions at 1 hour, which is fine for
  job-scoped credentials. **No long-lived AWS keys in any hosting model.**
- Azure and GCP hosting modules (Phase 4) mirror this design with Container Apps/AKS, Flexible
  Server, Key Vault and App Gateway/Front Door + WAF, and Cloud Run/GKE, Cloud SQL, Cloud KMS and
  an HTTPS LB + Cloud Armor.

## Consequences
- A secure, opinionated reference that matches the threat model. The cost is mostly NAT, ALB,
  RDS Multi-AZ and WAF, and is documented with a small and a production sizing profile.
- Two IaC formats double the review surface. The parity test and single-source policies contain
  the drift.
- ECS keeps the owner's production free of Kubernetes. EKS users get the Helm path.

## Alternatives considered
- Terraform only: less friction, but the brief asks for a CloudFormation template too (for
  console-only users).
- AWS CDK generating CloudFormation: another toolchain and language to maintain.
- App Runner: fewer networking controls (VPC egress, WAF integration) and more limits.

## References
- AssumeRoleWithWebIdentity: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- IAM Roles Anywhere: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
- Role chaining session limit: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html
- KMS encryption context in key policies: https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html
- GitHub OIDC to AWS: https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
