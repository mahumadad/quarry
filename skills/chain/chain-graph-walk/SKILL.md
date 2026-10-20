---
name: chain-graph-walk
description: >
  Build and walk the engagement's pivot graph using `chain_engine.py`'s `build_pivot_graph()`
  and `find_paths()` (BFS) to find every route from an initial-access node to a crown-jewel
  node (admin, RCE, full data access) across confirmed findings — the multi-hop complement to
  chain-analysis's pairwise matrix mode. Use for `/pt:chain --graph` or `--full`, once crown
  jewels are defined and at least one CONFIRMED/EXPLOITED finding exists. Do NOT use for
  pairwise scoring of finding combinations — that's chain-analysis's matrix mode; this skill
  only operates on the graph once nodes/edges exist, and routes shape matches to the named
  pattern skills same as any other candidate.
metadata:
  type: chain
  phase: chaining
  tools: [chain_engine.py, pivot-graph.md]
depends_on: [chain-analysis, capability-map, trust-map]
feeds_into: [finding-validation, report-writing]
chains_with: [chain-custom, chain-multi-app]
---

## Signals

- Two or more CONFIRMED/EXPLOITED findings exist and crown jewels have been defined with the
  client (per `references/chains/pivot-graph.md`) — without a defined destination the graph
  has no target to walk toward.
- `chain-analysis`'s matrix mode found pairwise links but the engagement wants to know whether
  those links chain *further* (3+ hops) toward the actual highest-value asset.
- A finding's own capability-map entry shows high out-degree (it unlocks many subsequent
  capabilities per `capability-map`'s "leverage point" note) and it's worth checking what that
  actually reaches.

## Prerequisites

- Crown jewels explicitly defined with the client (e.g. `crown_jewel:customer_pii_database`,
  `crown_jewel:payment_processing`, `crown_jewel:ci_cd_control`).
- `capability-map` and `trust-map` complete — nodes/edges in the graph are built from their
  output (asset/identity/capability triples and verified boundary crossings).
- `chain_engine.py --help` checked if flags have changed since last use (project CLI rule).

## Methodology

1. **Confirm the node vocabulary before building.** Per `pivot-graph.md`: nodes are
   access/capability states (`unauthenticated`, `authenticated:user_basic`,
   `access:db:read_only`, `crown_jewel:{{asset}}`), not findings themselves. If this vocabulary
   hasn't been applied consistently across prior mapping skills, normalize it here before
   building edges — mismatched node naming silently breaks path-finding.

2. **Build the graph.** `ChainEngine.build_pivot_graph(findings, assets)` — nodes = assets +
   capabilities reached via `ENABLES_MAP`; edges = each `CONFIRMED`/`EXPLOITED` finding that
   transitions one node to another, tagged with `finding_id`, the technique, and a confidence
   of `demonstrated` or `theoretical`. Never add an edge from a finding below `CONFIRMED` —
   per `pivot-graph.md`, unproven findings don't get to assert graph edges.

3. **Identify the initial-access node(s).** The first finding exploitable from the attacker's
   starting position with no prior credential — if the engagement is gray/white-box, start
   from the provisioned access level instead of `unauthenticated`.

4. **Run BFS from each initial-access node to the crown-jewel keywords.**
   `ChainEngine.find_paths(graph, start=<initial_access_node>, goal_keywords=[...])` — BFS is
   deliberate, not DFS: it returns the shortest paths first, which matches CVSS's Attack
   Complexity intuition (fewer hops = more practical = more reportable) and caps at 50 paths to
   avoid combinatorial explosion on larger graphs.

5. **Zero paths found is a valid, reportable result — not a failure.** State it plainly: with
   the findings confirmed so far, no known route reaches the defined crown jewels. This is
   coverage information (per project CLAUDE.md's "cobertura" rule) that should feed back into
   `/pt:hunt` — specifically, identify which node class is missing an inbound edge and target
   that gap next.

6. **Rank returned paths.** Shortest first (already BFS-guaranteed), then prefer paths where
   every edge is `demonstrated` over paths containing any `theoretical` edge — the former are
   reportable chains now, the latter are candidates requiring further validation before they
   can be presented with the same confidence.

7. **Filter by the modeled threat actor before reporting any path.** A graph-theoretically valid
   path that assumes physical access, or an identity the modeled attacker (external,
   unauthenticated vs. a malicious insider) wouldn't hold, is excluded from the primary result
   set and noted separately as "theoretical, wrong threat model" rather than silently included.

8. **Stop any path at the scope boundary.** If a route crosses into an asset outside the
   authorized scope, truncate the path there, document how far it reaches within scope, and
   flag that extending it would require new authorization — never walk or verify beyond that
   point without explicit sign-off (per project CLAUDE.md human-gates rule).

9. **Route each surviving path to the matching chain-* skill** for PoC development exactly as
   `chain-analysis` does for matrix-mode candidates — match shape to a named pattern
   (chain-web-to-rce, chain-auth-to-takeover, etc.) or to `chain-custom` if novel, and to
   `chain-multi-app` specifically if the path crosses an application/trust boundary that
   `trust-map` flagged as an org/tenant boundary rather than an internal one.

10. **Record bottleneck and high-leverage nodes.** Per `pivot-graph.md`'s reading guidance: a
    node reached by only one edge toward a crown jewel is the highest-ROI single remediation
    point for the client — call this out explicitly in the chain write-up even if the path
    itself isn't the most severe one found.

## Validation gate

- Every edge in the graph traces to a specific `CONFIRMED`/`EXPLOITED` finding ID — no edge
  exists from assumption or architecture-diagram claims alone.
- Every returned path has been checked against the modeled threat actor and the defined scope
  boundary before being handed to a chain-* skill.
- A zero-path result states explicitly which crown jewel(s) have no known route and why (no
  inbound edge found, vs. a found-but-filtered-out theoretical/out-of-scope route).
- Any path containing a `requires_human_gate: true` edge that hasn't been executed is reported
  as "viable, pending authorization for the final hop" — never presented as completed.

## Gotchas

- BFS with globally "visited" nodes will under-report on graphs where revisiting a node via a
  different edge is meaningful (small engagement graphs) — per `pivot-graph.md`, use
  per-path visited sets for typical engagement sizes (tens of nodes), and only fall back to
  depth-limited global-visited BFS if the graph is large enough to risk combinatorial
  explosion.
- A path that's graph-theoretically shortest isn't automatically the most severe — rank for
  reportability (demonstrated edges, practical attacker position) separately from rank by hop
  count.
- Two different-looking paths that both route through the same single finding aren't two
  independent chains worth reporting separately — check for this exact overlap before treating
  multiple BFS results as distinct findings for the report.
- Recalculate the graph incrementally as new findings are confirmed during the engagement —
  per `pivot-graph.md`, a late finding can complete an earlier dead-end path; don't treat a
  "zero paths" result from early in the engagement as final.
