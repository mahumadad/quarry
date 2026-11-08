---
name: quarry:chain
description: Analiza combinaciones de findings — matriz pairwise, grafo de pivoteo, o ambos. El comando clave del plugin.
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:chain [--matrix|--graph|--full]

This is the plugin's differentiating command (`engine/chain_engine.py`).
A typical manual pentest reports isolated findings; this command
systematically searches for combinations of minor findings that produce
critical combined impact, and for pivot paths from initial access to the
crown jewels defined in the target card.

By default (no argument), runs `--full` (matrix + graph).

## Precondition

- At least 2 findings with status `CONFIRMED`, `EXPLOITED`, or
  `CHAINED` must exist (`FindingsStore.list_chainable()`). If there are
  0 or 1, report that there is not enough material to chain and suggest
  `/quarry:hunt` first — this is not an error, it is a normal early
  engagement state.
- Read the 5 maps from `/quarry:map` if they exist — the capability map
  in particular defines what counts as a "crown jewel" for graph mode.

## Matrix mode (`--matrix`)

Pairwise combinatorial analysis over all chainable findings:

1. Load findings with `FindingsStore.list_chainable()`.
2. Run `ChainEngine.analyze_matrix(findings)` — internally:
   - Compares each pair `(F_i, F_j)` against `KNOWN_CHAINS` (known
     patterns: IDOR+no-rate-limit→mass-exfil, XSS-stored+CSRF→ATO,
     SSRF+cloud-metadata→credential-theft, etc. — see
     `references/chains/chain-matrix.md` for the full catalog, plus
     any operator-specific patterns from prior engagements).
   - Also expands `ENABLES_MAP` (which class enables exploitation of
     which other, beyond exact cataloged pairs).
   - Deduplicates candidates by `(findings frozenset, name)`.
3. Each candidate `Chain` is persisted in `chains.json` with
   `status="candidate"` and `evidence_tag="inferred"` — **a candidate
   chain is NOT a validated finding**. It is a structural hypothesis
   that must pass through `/quarry:validate` before being reported.
4. For each candidate with `critical` or `high` severity, attempt to
   manually verify the combination (chain the two PoCs in practice)
   before passing it to validation — if the combination does not
   reproduce in practice (e.g. the rate-limit does cut after N
   requests, higher than expected but not infinite), lower its
   severity or mark it `killed` with the reason.

## Graph mode (`--graph`)

Builds the pivot graph and searches for paths to crown jewels:

1. `ChainEngine.build_pivot_graph(findings, assets)` — nodes = assets +
   capabilities obtained (`"<asset>:<capability>"` via `ENABLES_MAP`),
   edges = findings that enable the hop.
2. Identify the "initial access" node(s) (the first exploitable finding
   without credentials, or the first entry point from the capability
   map).
3. Identify "crown jewel" keywords from the target card (question 2)
   and the capability map — e.g. `["admin", "database", "payment",
   "pii"]`.
4. `ChainEngine.find_paths(graph, start=<initial_access>, goal_keywords=[...])`
   — BFS returning up to 50 paths. If there are 0 paths, this is not a
   command failure: it means that with the current findings there is no
   known path to the crown jewels, and that is valid information for the
   report (a gap, neither success nor failure).
5. Prioritize the shortest paths (fewer chained findings = more
   practical chain to execute and more credible to the client).

## Exact steps (mode `--full`, default)

1. Run full matrix mode.
2. Run full graph mode.
3. Cross-reference results: any chain from graph mode that matches a
   matrix candidate is marked as doubly confirmed (higher confidence).
4. Write `<audit_dir>/report/chains.md` (Write tool) using
   `templates/chain-report.md` if it exists, otherwise with this
   structure per chain: name, involved findings (IDs + 1 line each),
   mechanism description, combined impact, combined severity,
   evidence_tag, and — if applicable — the full graph path.
5. Do not automatically transition individual findings to `CHAINED` —
   that requires the specific chain to pass the human gate and
   `/quarry:validate`. Here they are only registered as candidate
   `chain_refs`.

## Edge cases

- **Low-severity findings that combine into critical**: these are
  exactly the command's purpose — do not discard them for low individual
  severity. Report them with the same detail as "obvious" chains.
- **Two findings with the same root cause** (not yet deduplicated):
  matrix mode may generate a spurious "chain" between two symptoms of
  the same bug. Flag the duplicate suspicion in the output and recommend
  `/quarry:validate --all` (dedup step) before trusting that chain.
- **Graph with no clear initial access** (all findings require prior
  authentication): document this explicitly — it is a signal that an
  authentication/bypass finding is missing for the full kill chain to
  be viable, useful for directing the next `/quarry:hunt`.
- **Chain that crosses outside the original scope** (e.g. the pivot
  reaches an unauthorized asset): stop that chain branch at the scope
  boundary, document how far it reaches within authorized scope, and
  report to the operator that there is an unverifiable pivot path
  without expanding scope — never verify it without new authorization.

## Expected output

- List of candidate chains (matrix) with combined severity, ordered
  from highest to lowest impact.
- Pivot graph paths from initial access to crown jewels (if any), with
  each path's length.
- Path to `chains.md`.
- Recommended next step: `/quarry:validate` on the candidate chains and
  findings before reporting anything as confirmed.
