# 0011. Customer onboarding: Launch Stack with secure auto-registration, StackSets, single-source permissions

- Status: Proposed (design in Phase 0; AWS implementation in Phase 1, other providers in their phases)
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Brief §3a makes onboarding a first-class feature: connect in **under 5 minutes, in a few clicks,
without copy-pasting ARNs or secrets**, and see exactly what is being granted.

- For AWS that means a CloudFormation **quick-create "Launch Stack" URL** that
  **auto-registers** back to Skyline, and **StackSets** for whole organisations.
- Every cloud needs a Terraform alternative and versioned, least-privilege, CI-scanned templates.
- Each flow needs a permissions preview.

Constraints:
- Onboarding is the most security-sensitive interaction Skyline has with a customer. It creates a
  trust relationship into their account, and it has an internet-facing callback.

Verified facts this design depends on:
- Quick-create `templateURL` must be an S3 URL, and parameters are passed as `param_<Name>`.
  **`NoEcho` parameters are skipped** in quick-create links.
  ([CloudFormation quick-create links](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html))
- A custom resource's ServiceToken must be a Lambda or SNS topic in the same region, and the
  provider must write SUCCESS or FAILED to a pre-signed S3 `ResponseURL`, or the stack operation
  fails. ([custom resource reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/crpg-ref.html))
- Service-managed StackSets need trusted access with Organizations, run from the management or a
  delegated-admin account, support auto-deployment to accounts added to target OUs, and **never
  deploy to the management account**.
  ([StackSets with Organizations](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-associate-stackset-with-org.html))
- The `sts:ExternalId` condition protects against the confused-deputy problem when the third
  party generates a unique value per customer.
  ([confused deputy](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html))

## Decision

### Provider-agnostic model
- An `OnboardingFlow` protocol with `start`, `register` and `verify`, returning an
  `OnboardingSession` (launch URL, versioned artefacts with SHA-256, permissions preview,
  expiry).
- Integration states: `pending_registration → verifying → connected` (then `access_lost` or
  `disabled`).
- **No inbound message can mark an integration connected.** Only a successful worker-side
  verification can.

### AWS single account
1. An admin clicks **Connect AWS**. The API (`onboarding:start` permission, CSRF-protected,
   audit-logged) creates:
   - a `pending_registration` integration
   - a Skyline-generated **ExternalId** (≥ 128-bit random, unique per integration, never
     user-editable)
   - a **registration token**: 256-bit, only its SHA-256 stored, TTL ≤ 60 minutes, bound to
     tenant + integration, single use
2. The UI opens the quick-create URL. It carries the versioned S3 `templateURL` and pre-fills
   `param_SkylinePrincipalArn` (the Skyline **worker role ARN**), `param_ExternalId`,
   `param_RoleName`, `param_CallbackUrl` and `param_RegistrationToken`.
3. The template creates the read-only role (path `/skyline/`):
   - Trust: **only the specific Skyline worker role ARN**, with `sts:ExternalId`. Max session
     duration 1 hour.
   - Permissions: AWS-managed `SecurityAudit` + `ViewOnlyAccess`, or a tighter custom policy
     (choice and list verified in Phase 1), plus **explicit denies on data-plane reads** (e.g.
     `s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`,
     DynamoDB item reads; final list in Phase 1).
   - The role is tagged `skyline:template-version`.
4. A **Lambda-backed custom resource** registers back:
   - Inline code, no dependencies, an execution role with only logs permissions, TLS verification
     on, 10-second timeout.
   - It POSTs `{token, role_arn, account_id, stack_id, region, template_version}` to the callback.
   - It **always reports SUCCESS** to CloudFormation, with `Data.Registered` true or false, so
     the customer's stack never hangs or rolls back because Skyline is unreachable. A stack
     output tells the user whether to use the paste-ARN fallback.
   - Update and Delete events only *notify* Skyline, which re-verifies.
5. **Callback** `POST /api/v1/onboarding/aws/register`:
   - Authentication: public route with token auth (no session, no CSRF), listed explicitly in the
     public-route allowlist test. The token is compared in constant time and consumed atomically
     (`UPDATE … SET consumed_at = now() WHERE token_hash = :h AND consumed_at IS NULL AND
     expires_at > now() RETURNING tenant_id, integration_id`) through a `SECURITY DEFINER`
     function.
   - Input validation: strict schema (`extra="forbid"`), a body cap of about 8 KB. The ARN must
     match the partition allowlist and the `/skyline/` path, and its account must match
     `account_id`.
   - Abuse handling: generic `202` whether or not the token exists, per-IP and global rate limits
     (plus a WAF rule in the AWS deployment), and every attempt audit-logged.
   - Effect: it only moves the integration to `verifying` and enqueues `verify_integration`.
6. **Worker verification:** `sts:AssumeRole` with the integration's ExternalId and a 15-minute
   session, then a minimal read probe (`sts:GetCallerIdentity`, `iam:ListRoleTags` on its own
   role) to confirm the account and template version. Then `connected`, the account ID shown
   prominently in the UI, the first scan enqueued, and an audit entry.
7. **Fallbacks:** paste the role ARN (for self-hosted Skyline that AWS can't reach), or the
   Terraform module in `deploy/terraform/onboarding/aws/`. Both go through the same verification.

### Exception: registration token in a URL
Because CloudFormation skips `NoEcho` parameters in quick-create links, the token is a normal
stack parameter. It is visible in browser history and to principals with
`cloudformation:DescribeStacks` in the customer account. This is a **recorded exception** to
`SECURE_CODING.md` "no secrets in URLs", accepted because:
- the token is single-use, valid for at most 60 minutes and bound to one integration
- it is worthless once consumed, which normally happens within seconds of stack creation
- it can't connect an integration on its own: the worker must still assume a role that trusts
  Skyline's principal with that integration's ExternalId

An unused token expires without any effect. The UI lets an admin revoke an unused token and
issue a new one.

### AWS organisation (StackSets)
- One quick-create stack in the **management account** creates:
  - the management-account read-only role, plus `organizations:Describe*` / `List*` for discovery
  - a **service-managed `AWS::CloudFormation::StackSet`** (auto-deployment on, targets = chosen
    OUs, root by default) that deploys the member role with the same path, name and ExternalId
  - the registration custom resource
- The wizard checks that trusted access is enabled and explains how to enable it.
- **Members are discovered, not self-registered.** The worker lists org accounts through the
  management role and assumes `/skyline/<RoleName>` in each one. Missing roles show as "pending
  deploy" or "role missing". There are no multi-use or long-lived registration tokens.
- The management account is covered by its own stack, because StackSets never deploy there.

### Single source of permissions and template lifecycle
- `deploy/onboarding/aws/policy/*.json` (allowed actions, explicit denies, trust shape) is the
  only place permissions are defined. A generator renders the CloudFormation templates (single
  account, management account, member StackSet), the Terraform module and the UI's
  **permissions preview**. CI regenerates them and fails on any diff.
- Every permission line carries a short "why" comment in the source, as `SECURE_CODING.md`
  requires.
- Templates are semver-versioned and immutable once published:
  - Hosted at `templates/aws/vX.Y.Z/` in the operator's templates bucket (ADR-0012), with their
    SHA-256 shown in the UI and release notes.
  - Published only by the release pipeline (GitHub OIDC role, protected environment).
  - The connector reads `skyline:template-version` and the UI offers an **update stack** link
    when it's outdated.
- CI checks every template with cfn-lint, checkov or Trivy config, and `terraform validate`.
- **Add-on stacks** for higher privileges (snapshot scanning, DSPM, opt-in remediation) are
  separate templates with separate roles. The base role never grows beyond read-only.

### Other providers (design intent)
- **M365 / Entra:** Skyline is a **multi-tenant Entra app**, and onboarding is one admin-consent
  link with `state` bound to the session.
  - The app's client-assertion signing key is held in KMS or Key Vault and used through the
    sign operation, so the private key never leaves the HSM. This one credential reaches every
    M365 customer, so it is the most sensitive secret Skyline holds.
  - Self-hosters register their own app with a guided script.
- **Google Workspace:** a DWD wizard with copy buttons, the exact `*.readonly` scopes, a test
  connection step and a prominent DWD warning. Investigate a Marketplace app.
- **Azure:** Deploy-to-Azure / Cloud Shell one-liner plus admin consent, with Reader + Security
  Reader at management-group scope. Certificate or WIF credentials, never client secrets.
- **GCP:** Cloud Shell / Terraform with WIF, `roles/viewer` + `roles/iam.securityReviewer` at
  org or folder scope.
- Every flow gets fixture-based CI tests and a manual sandbox end-to-end test, run only with the
  owner's approval.

## Consequences
- Onboarding matches the category bar, and every registration path still ends in independent
  verification.
- The callback is an internet-facing unauthenticated endpoint. It is small, rate-limited,
  WAF-protected in AWS and heavily tested (replay, expiry, wrong tenant, malformed ARN, oversized
  body, timing).
- Each customer account gets a small Lambda (inline code, logs-only), which reviewers can read in
  the template. Its runtime must be kept current through template updates.
- A self-hosted Skyline that AWS can't reach loses auto-registration, but keeps paste-ARN and
  Terraform.

## Alternatives considered
- **SNS-backed custom resource** pointing at a topic in Skyline's account: needs a cross-account
  publish policy (effectively a wildcard principal) and requires Skyline to run on AWS.
- **No token, verification only:** simpler, but anyone who learns an ExternalId could attach
  their own account to a victim's integration, and it removes the short time window.
- **Per-integration template objects** with the token baked in: leaves a token-bearing object in
  S3, and breaks immutability and checksum display.
- **Self-registration of StackSet members** with a multi-use org token: creates a long-lived
  credential. Discovery is simpler and safer.

## References
- See the links in Context. Phase 1 adds the managed-policy and data-plane-deny references.
