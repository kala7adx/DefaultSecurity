# 0005. Layered read-only enforcement for connectors

- Status: Accepted (owner approval 2026-11-23)
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
   - (amended 2026-11-24) the AST rules allowlist imported *names*, not just modules; only the
     registry may import gateways, transports or the runner; reflection built-ins, `importlib`,
     `get_type_hints`, `ImportString`/`TypeAdapter`, dunder and foreign private attributes are
     banned. A corpus of known bypasses is tested. These rules are a **tripwire**: Python can't
     isolate code inside one process, so layers 1 and 3 are the real boundaries.
5. **SDK hook (Phase 1):** a boto3/botocore `before-call` event handler applies the same
   allowlist inside the SDK, as defence in depth (verify event names in Phase 1).

Runtime details (amended 2026-11-24 after the Phase 0 re-review):
- `ApiNotAllowedError` derives from `ReadOnlyGuardError`, **not** `ConnectorError`, so connector
  code catching provider errors can't swallow it. The gateway and the transport both refuse, and
  the gateway records every refusal; the worker checks that record after each step. Any
  violation fails the whole scan, stores nothing and writes a `connector.read_only_violation`
  audit row (a violation during verify leaves the integration's status alone and isn't retried).
- The SDK deny list (`DENIED_SDK_OPERATIONS`) is a tripwire too; names are re-checked against
  the AWS Service Authorization Reference when each service gets a collector.
- HTTP connectors (Phase 2+): allowlist entries are path *templates*. The HTTP transport must
  percent-encode every path parameter (`quote(value, safe="")`), reject `/`, `..` and encoded
  separators in parameter values, and allowlist query parameters per operation (no `alt=media`,
  `$value`, `$expand` into content). Checked on each call, not only at registration.

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
