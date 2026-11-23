# Contributing to Skyline

Thanks for helping. Before you write code, read:

- [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md): what we are building
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the [ADRs](docs/adr/README.md): how
- [docs/SECURE_CODING.md](docs/SECURE_CODING.md): the rules every change must follow

## Ground rules

- **Connectors are read-only.** Every connector declares an allowlist of read API calls, and the
  build fails if it calls anything else. Remediation code needs an ADR first.
- **No secrets** in code, fixtures, tests, logs, error messages, URLs or commit history.
- **No copied vendor material.** Do not copy code, documentation, rule text or UI from Wiz, Orca
  or any other vendor. Write check descriptions and control wording in your own words.
- **Licences:** dependencies must be Apache-2.0, MIT, BSD, ISC or MPL-2.0 (see ADR-0010).
  GPL, LGPL, AGPL, SSPL and BSL dependencies are not accepted.
- Significant decisions get an ADR in `docs/adr/`.

## Development setup

You need `uv`, `pnpm`, Node.js LTS and Docker. Then:

```sh
uv sync
pnpm install
pre-commit install
```

## Before you open a pull request

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run pytest
pnpm --dir apps/web lint && pnpm --dir apps/web typecheck && pnpm --dir apps/web test
```

- Write tests with the code. A check needs a passing and a failing fixture.
  Security-relevant code needs negative tests.
- Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:` …).
- A new direct dependency needs a short justification in the commit message: purpose, licence,
  maintenance status and adoption.

## Adding a check

Add a YAML definition under `packages/checks/src/skyline_checks/definitions/<provider>/`, an
evaluator under `evaluators/`, and `pass.json` / `fail.json` fixtures under
`packages/checks/tests/fixtures/<check_id>/`. Framework mappings go in
`packages/frameworks/src/skyline_frameworks/mappings/`. No other changes are needed.
