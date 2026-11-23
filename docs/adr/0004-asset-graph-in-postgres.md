# 0004. Asset graph in Postgres (nodes/edges tables)

- Status: Accepted (owner approval 2026-11-23)
- Date: 2026-11-23
- Deciders: Owner, Claude Code

## Context
Prioritisation (brief §2, §6; Phase 7) relies on a security graph: internet-exposed VM →
security group → instance role → bucket tagged PII. A dedicated graph database (Neo4j, Neptune)
adds operational burden, and the popular ones have licence or vendor lock-in concerns (Neo4j
Community is GPL-3.0). Brief §4 says to start in Postgres and revisit via ADR only when query
needs prove it.

## Decision
- `assets` is the node table and `relationships` is the edge table (`src_asset_id`,
  `dst_asset_id`, `type`, `properties`), both tenant-scoped with RLS. There are indexes on
  `(tenant_id, src_asset_id)` and `(tenant_id, dst_asset_id)`.
- Traversals use recursive CTEs with an explicit depth cap and cycle detection (`CYCLE` clause),
  wrapped in a small query layer in `skyline_core.graph`. Evaluators get a read-only
  `EvalContext.related()` view.
- Edge identity uses native IDs during collection. The runner resolves them to asset IDs once
  both ends exist; edges to unseen nodes are kept as dangling references and resolved on later
  scans.
- Phase 7 benchmarks a synthetic 50k-asset tenant and writes a follow-up ADR on whether a graph
  store is needed.

## Consequences
- One database to back up, secure, apply RLS to and deploy anywhere.
- Deep or wide traversals may get slow at scale. Mitigations: depth caps, materialised
  "exposure" columns computed after each scan, and the Phase 7 benchmark.

## Alternatives considered
- Neo4j: GPL-3.0 community edition, plus a separate service.
- Amazon Neptune: AWS-only, which breaks deploy-anywhere.
- Apache AGE extension: Apache-2.0, but not available on all managed Postgres offerings.

## References
- Recursive queries and `CYCLE`: https://www.postgresql.org/docs/current/queries-with.html
