# 0005. Layered read-only enforcement for connectors

- Status: Proposed
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
`CLAUDE.md` rule 1: connectors may only call read APIs, each connector declares an allowlist,
and a test fails the build on any call outside it. Read-only access is both a selling point and
a core safety property. A single control, such as only the IAM policy, is too weak: customers
may attach broad policies, and a bug or a compromised dependency could issue write calls.

## Decision
Enforce read-only access in five independent layers:

1. **Customer-side permissions:** onboarding templates grant read-only actions, plus explicit
   denies on data-plane reads (`s3:GetObject`, `secretsmanager:GetSecretValue`,
   `ssm:GetParameter*`, `kms:Decrypt`, …; the full list is verified in Phase 1). Graph and
   Google grants use read-only permissions and `*.readonly` scopes only.
2. **Declared allowlist:** each connector class has `api_allowlist: frozenset[ApiCall]`, checked
   at import time against the provider's read-only pattern:
   - AWS operations must match `^(Describe|List|Get)[A-Z]`.
   - HTTP connectors allow `GET` only. A named list of read-only `POST` query endpoints is
     allowed only with an ADR note for each entry.
3. **Runtime gateway:** connectors receive an injected `ApiGateway`, which raises
   `ApiNotAllowedError` for any call outside the allowlist and logs and audits the attempt.
   Connectors never construct SDK clients themselves.
4. **Tests that fail the build:**
   - each connector runs over its fixtures with a recording gateway, and its calls must be a
     subset of its allowlist
   - a deliberately rogue test connector must be rejected
   - an AST test forbids importing provider SDKs or HTTP clients (`boto3`, `botocore`, `httpx`,
     `requests`, `urllib`, `socket`, `msgraph`, `googleapiclient` …) in connector modules other
     than the gateway adapters
5. **SDK hook (Phase 1):** a boto3/botocore `before-call` event handler applies the same
   allowlist inside the SDK, as defence in depth (verify event names in Phase 1).

Remediation or any write capability needs a new ADR, a separate opt-in permission stack, and a
separate connector identity (brief §11 "Remediation").

## Consequences
- A connector bug or a malicious change can't issue writes without failing CI and runtime checks
  first. Even if one layer is bypassed, the IAM layer still blocks the call.
- Adding an API call means updating the allowlist: a one-line, reviewable diff.

## Alternatives considered
- IAM-only enforcement: depends on the customer's configuration and catches nothing in CI.
- Network egress proxy filtering by method: useful later for HTTP providers, but it can't parse
  the AWS JSON or Query protocols reliably.

## References
- AWS managed policies (verify choice in Phase 1): https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html
- botocore events: https://boto3.amazonaws.com/v1/documentation/api/latest/guide/events.html
