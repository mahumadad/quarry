---
name: static-analysis-toolkit
description: >
  Run real static analyzers (CodeQL, Semgrep) and parse their SARIF output into the
  finding pipeline. Use in any source-available engagement to ground the LLM-driven
  SAST agents with tool-generated evidence: build a CodeQL database, run query packs,
  author/run Semgrep rules, ingest SARIF results as leads with rule metadata.
  Keywords: codeql, semgrep, SARIF, static analysis, query pack, database create,
  taint tracking, rule authoring, analyzer output, scan ingest.
  Do NOT use for dependency/advisory auditing (supply-chain-audit) or for propagating
  a single confirmed pattern (variant-analysis) — this is the general analyzer layer.
metadata:
  type: sast
  phase: hunting
  cwe: [CWE-119]
  mitre_attack: [T1190]
  tools: [codeql, semgrep, sarif-tools]
depends_on: [code-review]
feeds_into: [finding-validation, variant-analysis]
chains_with: [sqli, xss, rce, deserialization, ssrf]
---

## Purpose

The SAST agents (entry-mapper, sink-finder, flow-tracer, devils-advocate)
reason about code. Analyzers MEASURE it. This skill wires CodeQL and Semgrep
into the pipeline: their output lands as structured leads (rule, severity,
source→sink path) that agents triage — combining analyzer recall with agent
judgment, and giving every SAST-derived finding a reproducible query behind it.

## Methodology

1. **Semgrep first (seconds to value):**
   ```bash
   semgrep scan --config auto --sarif -o semgrep.sarif .
   ```
   `--config auto` pulls registry rules matched to detected languages. Add
   focused packs per stack (`p/python`, `p/javascript`, `p/security-audit`,
   `p/owasp-top-ten`). Review rule selection — registry defaults are noisy on
   some stacks; record which packs ran for the coverage report.

2. **CodeQL for depth (taint tracking across the real call graph):**
   ```bash
   codeql database create db --language=python --source-root=.
   codeql database analyze db codeql/python-queries \
     --format=sarif-latest -o codeql.sarif
   ```
   Compiled languages need a working build (Java/C#/Go/C++): if the build
   fails, record it as a gap and fall back to Semgrep + agent review. Check
   `codeql` flags with `--help` per CLI anti-hallucination rules before first
   use.

3. **Ingest SARIF as leads, not findings.** Parse each result into: rule id,
   CWE, file:line, message, code-flow (source→sink steps). Deduplicate
   against existing findings (dedup skill). Feed high-signal classes
   (injection sinks, deserialization, path traversal, weak crypto) to the
   flow-tracer with the analyzer's code-flow as the starting hypothesis.

4. **Triage with the adversarial pipeline.** Analyzer results have real false
   positive rates (sanitizers the tool can't model, unreachable paths). Every
   promoted lead passes the standard validation gate + devil's-advocate
   rebuttal. The SARIF result is cited in the finding's evidence as the
   DETECTION record; the finding's proof remains the demonstrated trigger or
   the confirmed code-path trace.

5. **Custom queries for client-specific patterns.** When app-profile reveals
   custom frameworks (in-house ORM, custom auth decorator), write targeted
   Semgrep rules for THEIR sinks — generic packs miss custom wrappers.
   Deposit reusable rules in references/payloads/ (anonymized) per
   memory-first rules.

6. **Export loop.** On report, re-export final findings AS SARIF
   (engine/exporters.py to_sarif) so results land in the client's code
   scanning UI alongside their own analyzer runs — same format, one pane.

## Tooling

- `codeql database create/analyze` — multi-language taint analysis.
- `semgrep scan --sarif` — fast pattern scanning, custom rules.
- `sarif-tools` / `jq` — SARIF parsing, filtering, diffing between runs.
- engine/exporters.py — findings → SARIF for client code-scanning ingestion.

## Validation Gate (minimum proof)

- Analyzer hit + agent-verified code path (flow-tracer confirmation or
  live trigger). A SARIF result alone is never a finding — it is a lead with
  a rule citation. The finding must name the verifying query/rule so the
  client can reproduce detection internally.

## Gotchas

- **CodeQL database staleness:** re-create the DB after any repo change
  mid-engagement; analyzing stale code invalidates line references.
- **Language coverage gaps:** CodeQL/Semgrep cover mainstream languages;
  for exotic stacks (Solidity, niche templates, config-as-code) note the
  analyzer gap explicitly and rely on agent review.
- **Severity inflation:** analyzer severities ≠ finding severities. Re-score
  per CVSS 4.0 + context (internet-facing? authenticated? reachable?).
- **SARIF volume:** a default pack can emit thousands of results — filter by
  confidence/severity at ingest, keep the raw SARIF as an artifact, and
  record filter criteria in the coverage section.
- Respect scope direction: analysis happens on the client's code on YOUR
  machine — do not upload client source to hosted scanner services without an
  explicit operator gate (data handling).

## Chain Anchors

1. Analyzer finds an injection family → variant-analysis sweep with the same
   rule generalized.
2. Analyzer reports weak crypto / hardcoded secret → hunt live impact via the
   relevant skill (jwt, info-disclosure).
3. Clean analyzer run on a claimed-dangerous component → record as coverage
   evidence ("component X scanned with packs Y, zero high-confidence hits") —
   negative results belong in the report's coverage section.
