---
name: variant-analysis
description: >
  Propagate one confirmed vulnerability pattern across the entire codebase or API
  surface. Use immediately after ANY finding is confirmed with source access: extract
  the abstract pattern (sink + missing guard + dataflow shape) and search for siblings —
  same vulnerable call, same missing check, same endpoint template. Turns one finding
  into complete coverage of its class. Keywords: variant analysis, pattern propagation,
  codeql variant, semgrep rule from finding, siblings, same-bug-different-location,
  systematic coverage.
  Do NOT use before at least one finding is confirmed (that is hunting, not variant
  analysis) or without source/schema access.
metadata:
  type: sast
  phase: hunting
  cwe: [CWE-1004]
  mitre_attack: [T1190]
  tools: [semgrep, codeql, grep, ast-grep]
depends_on: [code-review, finding-validation]
feeds_into: [report-writing, chain-analysis]
chains_with: [sqli, xss, ssrf, idor, rce, auth-bypass]
---

## Purpose

Finding one SQLi is luck; finding ALL SQLi built the same way is analysis.
Clients fix the instance you report and leave the 11 siblings. Variant
analysis is the discipline that converts a confirmed finding into class-wide
coverage — and it's also how you verify a fix ("the patch closed endpoint A;
the same pattern in B, C, D remains").

## Methodology

1. **Abstract the confirmed finding into a pattern.** From the PoC, extract:
   - the SINK (exact function/API: `db.execute(`, `render_template_string(`,
     `exec(`, an HTTP client call...),
   - the missing GUARD (no parameterization, no authorization decorator, no
     allowlist check),
   - the SOURCE shape (request param → sink distance, any wrappers).
   Write it as a one-line predicate: "calls to X where argument contains
   request-derived data and no call to Y in the same handler".

2. **Encode the pattern as a query:**
   - Semgrep rule (fastest; one YAML per pattern, run in seconds),
   - CodeQL query when a database already exists (static-analysis-toolkit),
   - fallback: structured grep / ast-grep for simple shapes.
   Iterate until the rule fires on the ORIGINAL finding location — if it
   can't find the bug you know, it won't find its siblings.

3. **Sweep the whole repo / service map.** Every hit is a VARIANT CANDIDATE —
   not a finding. Triage each: same source reachability? same guard really
   absent? sanitization happening in a wrapper the pattern can't see?

4. **Confirm candidates per class rules.** Variants get the same evidence
   bar as the original: live trigger where in scope, or `Inferred` with the
   code-path evidence (source → sink trace + absent guard) clearly attached.
   Mass-reporting unverified variants violates the anti-fabrication rules.

5. **No-source variant analysis (black-box):** pattern = endpoint shape. If
   `/api/v1/users/{id}/export` had IDOR, enumerate sibling routes from
   api-discovery and replay the identity-swap (session-context) across all
   handlers sharing the route template. Route-naming symmetry is the pattern.

6. **Report as a family.** One finding per distinct root cause, with a
   variant table (location, status: demonstrated/inferred/not-reachable) —
   NOT 12 near-duplicate findings. Report-writing skill has the family format.

## Tooling

- `semgrep --config pattern.yml .` — primary pattern engine.
- `codeql database analyze` — deep dataflow variants on an existing DB.
- `ast-grep` / `sg` — fast syntactic sweeps.
- Router/framework route dumps (Rails routes, Flask url_map, OpenAPI paths)
  for black-box sibling enumeration.

## Validation Gate (minimum proof)

- The pattern rule demonstrably matches the original confirmed finding.
- Each reported variant carries: location, source→sink trace (or live
  evidence), guard-absence note, and status tag. Unverifiable variants go in
  the finding's variant table as `Inferred`, never as separate Demonstrated
  findings.

## Gotchas

- **Wrapper blindness:** sanitization/authorization in middleware or
  decorators makes naive patterns over-fire — extend the pattern with the
  wrapper's signature once discovered, and re-sweep.
- **Copy-paste drift:** siblings often have subtle differences (one HAS the
  check). Verify each hit individually; the pattern finds candidates, humans
  (validators) confirm.
- **Generated code and vendored dirs:** exclude `vendor/`, `node_modules/`,
  generated protobuf — or you'll drown in out-of-scope hits (supply-chain
  findings are the other skill's job).
- Record sweep coverage: files/routes searched, exclusions — the variant
  table's completeness claim depends on it.

## Chain Anchors

1. Variant family mapped → which variant sits on the highest-value asset
   (admin panel, payment service)? Retest that one first for Demonstrated.
2. Guard missing systematically (e.g., no authorization decorator anywhere in
   a service) → that is a structural finding: report root cause once, cite all
   affected routes.
3. Fix-verification mode: after client remediation, re-run the same pattern —
   unfixed siblings become the retest report's core content.
