# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Skyline is a security product that holds read access to customer clouds. Choices about the
stack, tenancy, crypto, permissions and deployment are expensive to reverse, and auditors
(ISO 27001, Cyber Essentials) value traceable decisions. `CLAUDE.md` says the tech stack changes
only through an ADR, and `docs/SECURE_CODING.md` says exceptions to the standard need an ADR.

## Decision
- We record significant decisions as Architecture Decision Records in `docs/adr/`, using the
  lightweight Nygard format: Status, Date, Deciders, Context, Decision, Consequences,
  Alternatives considered, References.
- Files are named `NNNN-kebab-title.md` with numbers that are never reused.
- Statuses: `Proposed` → `Accepted` → (`Deprecated` | `Superseded by NNNN`). Accepted ADRs aren't
  edited for substance. To change a decision, write a new ADR that supersedes the old one, and
  update the old one's status line.
- An ADR is required for:
  - a stack change
  - any new permission or scope a connector needs beyond read-only
  - any exception to `SECURE_CODING.md` or the `CLAUDE.md` security rules
  - new data stores or third-party services that receive customer data
  - each Phase 10+ parity item (per `prompts/01-PHASE-PROMPTS.md`)
- Vendor facts an ADR relies on get an official documentation link.

## Consequences
- Reviewers and auditors can trace why the platform looks the way it does.
- Each significant change costs a small amount of writing.
- `docs/ROADMAP.md` and `docs/THREAT_MODEL.md` link to the ADRs that justify mitigations.

## Alternatives considered
- Decisions only in PR descriptions: easily lost, not reviewable as a set.
- A wiki: lives outside the repo and drifts from the code.

## References
- Michael Nygard, "Documenting Architecture Decisions" (2011).
