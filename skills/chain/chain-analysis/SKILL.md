---
name: chain-analysis
description: >
  Main chain-analysis skill. Systematically analyzes all confirmed findings
  pairwise to find exploit chains that increase impact beyond any single
  finding. Runs chain_engine.py in two modes: matrix mode (brute-force
  pairwise scoring of every finding pair against the capability-map) and
  graph mode (build a pivot graph of footholds→capabilities→new footholds
  and walk it for multi-hop chains). Produces ranked chain candidates for
  the specific chain-* skills to develop into full PoCs.
  Use once two or more CONFIRMED findings exist for the engagement and
  capability-map/trust-map are available. Use keywords: chain, pivot,
  escalation path, combine findings, attack path.
  Do NOT use on unconfirmed/theoretical findings — feed confirmed findings
  only, per finding-validation's gates.
metadata:
  type: chain
  phase: chaining
  tools: [chain_engine.py, burp, custom_scripts]
depends_on: [asset-map, trust-map, identity-map, state-map, capability-map, finding-validation]
feeds_into: [chain-web-to-rce, chain-auth-to-takeover, chain-info-to-exploit, chain-ssrf-to-cloud, chain-xss-to-account-takeover, chain-idor-to-mass-data, chain-custom, report-writing]
chains_with: [chain-web-to-rce, chain-auth-to-takeover, chain-info-to-exploit, chain-ssrf-to-cloud, chain-xss-to-account-takeover, chain-idor-to-mass-data, chain-custom]
---

## Signals

- Two or more findings have passed finding-validation's gates and the engagement has budget
  left to look for combinations, not just report each in isolation.
- A single finding's impact looks capped ("just an info leak", "just a low-severity CSRF")
  but another finding on the same system might remove that cap.
- At a natural checkpoint (end of breadth-first coverage pass, per project CLAUDE.md
  "cobertura" rule: open 2-3 attack paths before going deep) — chain-analysis is exactly the
  "before going deep" step that decides which path is worth the depth.

## Prerequisites

- All five mapping skills completed (asset/trust/identity/state/capability-map).
- At least two findings that passed finding-validation (Gates 1-4) — this skill explicitly
  does not run on unvalidated hypotheses.
- `chain_engine.py` available and its `--help` checked before first use per the project's
  CLI anti-hallucination rule.

## Methodology

1. **Load inputs.** `chain_engine.py` ingests the confirmed-findings list, the capability
   matrix, and the trust-graph. Run `chain_engine.py --help` first to confirm current flags
   before scripting a call.

2. **Matrix mode — pairwise scoring.** For every unordered pair of confirmed findings
   (A, B), ask mechanically:
   - Does A's output become B's input (A's leaked data satisfies a precondition B needs)?
   - Does A's access level unlock a surface B needs reachability to (trust-map boundary
     crossed)?
   - Does A removing a control (rate limit, validation, auth check) remove a blocker that
     was the only thing capping B's impact?
   Score each pair 0 (no relation) / 1 (plausible, needs manual review) / 2 (clear precondition
   satisfied) using `chain_engine.py --mode matrix`. Pull every pair scoring ≥1 into manual
   review — do not auto-promote score-2 pairs without a human looking, scoring heuristics
   produce false positives on structurally-similar-but-unrelated findings.

3. **Graph mode — pivot graph.** Build a directed graph: nodes are (asset, identity,
   capability) triples; an edge exists when a confirmed finding transitions from one triple
   to another (e.g. anonymous+web-app → authenticated-low-priv+web-app via an auth bypass).
   Run `chain_engine.py --mode graph` to walk all paths from any anonymous/external starting
   node to any high-capability node (full DB access, code execution, payment processing,
   admin identity). Each such path is a chain candidate.

4. **Rank candidates.** Prefer chains that: cross the most privilege tiers per hop used (fewer
   findings for more impact gain), reach the capabilities the client's RoE flagged as highest
   concern (check the engagement scope doc), and are reproducible end-to-end within the
   engagement's remaining budget (project CLAUDE.md: respect the 100-tool-call/phase default).

5. **Route each candidate to its pattern skill.** Match the candidate's shape to the nearest
   chain-* skill (web→RCE, auth→takeover, info→exploit, SSRF→cloud, XSS→takeover,
   IDOR→mass-data) and hand it off with the specific finding IDs and the trust/capability
   edges that justify the link. If no pattern fits, route to chain-custom.

6. **Record dead ends.** Per project CLAUDE.md "cobertura" rule, a pair/path that scored high
   but failed manual review or failed reproduction is logged as a dead end with the reason —
   this prevents re-deriving the same non-chain later and is itself reportable coverage.

## Validation gate

- No chain candidate is promoted to a chain-* skill without the specific findings (by ID),
  the specific trust/capability edge justifying the link, and a stated reproduction plan.
- Every chain ultimately handed to report-writing must independently satisfy finding-
  validation's four gates for the *combined* impact, not just inherit validity from its
  component findings.
- Human gate per project CLAUDE.md: any chain whose reproduction requires modifying target
  state gets explicit operator confirmation before execution, even if every component finding
  was individually already approved.

## Gotchas

- Pairwise matrix mode is O(n²) and gets noisy past ~30 findings — pre-filter to findings
  with nonzero capability/trust-map evidence before running it at scale, or let graph mode
  carry the load for larger engagements.
- A chain can be real and still not worth reporting as a single finding if each component is
  independently critical already (don't manufacture a chain narrative to inflate a report
  that's already strong) — chain the ones that genuinely change the severity picture.
- Two findings on the "same" endpoint are not automatically a chain — verify the actual data/
  control dependency, not just co-location.
- A chain that only works against a staging/test fixture (seeded data, disabled rate limit
  for QA) is not a valid prod chain — re-verify every hop's preconditions hold in the
  actually-in-scope environment.
- Graph mode will find paths that are theoretically connected but practically require
  privilege the attacker model doesn't grant (e.g. assumes physical access) — filter by the
  engagement's defined threat actor before ranking.
