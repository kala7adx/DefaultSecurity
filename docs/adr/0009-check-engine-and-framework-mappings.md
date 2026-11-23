# 0009. Check engine: YAML metadata + registered Python evaluators; mappings in frameworks

- Status: Proposed
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Brief §4: checks are data + code, with YAML metadata and a pure `evaluate(asset, context) ->
Result(status, evidence)`, and an interface that leaves room for Rego, CEL or graph evaluators.
§10: a new check needs no code changes outside `packages/checks/`. §7: mappings are
many-to-many, start as `reviewed: false`, and must not reproduce copyrighted benchmark text. The
kickoff places the framework catalogue and the stub mappings in `packages/frameworks`.

## Decision
- **Check metadata in YAML**, validated by Pydantic with `extra="forbid"` and loaded with
  `yaml.safe_load`.
  - Fields: `id` (dotted `provider.service.name`), `version`, `title`, `severity`, `provider`,
    `resource_types`, `evaluator` type, `description`, `rationale`, `remediation`, `references`
    (official URLs), `tags`.
  - The loader rejects duplicate IDs, unknown resource types and missing evaluators.
- **Evaluators** are registered with a decorator under the check ID (`@evaluator("fake.network.
  sg_admin_ports_open")`). **YAML never contains import paths or code.** This blocks
  YAML-to-arbitrary-import injection.
  - Evaluators are pure: no I/O, and only a read-only `EvalContext` for related assets.
- **Result semantics:** `pass | fail | error | not_applicable`. Only `pass` resolves a finding.
  `error` is isolated to that asset and check, and is reported.
- **Fixtures are mandatory:** a parametrised test requires `tests/fixtures/<check_id>/pass.json`
  and `fail.json` for every check, and that they produce `pass` and `fail`.
- **Mappings live in `packages/frameworks/mappings/<framework>.yaml`** (check ID → control refs,
  `reviewed`, rationale), and catalogues in `catalogues/`. Keeping them separate means:
  - review-state changes and framework version updates (such as Cyber Essentials v3.2 → v3.3)
    don't bump check versions
  - compliance reviewers own one file
  - a new check can ship unmapped without touching frameworks code (unmapped checks are listed)
- At migrate time a **catalogue sync** writes checks, frameworks, controls and mappings into the
  global read-only tables. `content_hash` detects edits, and an edit without a version bump fails
  CI.

## Consequences
- Adding a check means writing YAML, an evaluator and two fixtures, all in `packages/checks/`.
- The brief's line "check YAML includes framework mappings" is satisfied by reference, with
  mappings kept in a separate file. That's a small deviation from the brief, recorded here.

## Alternatives considered
- Mappings embedded in check YAML: simpler at first, but couples compliance review to check
  versioning.
- Rego (OPA) as the primary evaluator: powerful, but a heavier toolchain. It stays a future
  evaluator type behind the same contract.

## References
- PyYAML `safe_load`: https://pyyaml.org/wiki/PyYAMLDocumentation
