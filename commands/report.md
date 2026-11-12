---
name: quarry:report
description: Generate the engagement report — full or executive summary only, Markdown or PDF
argument-hint: "[--format md|pdf] [--executive]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:report [--format md|pdf] [--executive]

Generates the final engagement report from `VALIDATED` findings and
verified chains. Defaults to `md` format, full report (not executive
only).

## Precondition

- There must be at least 1 finding with status `VALIDATED` or `REPORTED`
  (`FindingsStore.list_by_status(FindingStatus.VALIDATED)`). If there
  are none, stop and point out that `/quarry:validate` is missing — a
  report without validated findings is, at best, a recon/coverage
  report, not a findings report. Offer to generate an "engagement
  status" report if that is what the operator wants, but do not call it
  a findings report.
- Findings in `STALL`, `DETECTED` or `CONFIRMED` (not validated) **do
  not enter the report** as confirmed findings. If the operator insists
  on including them, they must appear in a separate, clearly labeled
  "not validated / in progress" section, never mixed with the main list.

## Arguments

- `--format md` (default) — Markdown in `<audit_dir>/report/`.
- `--format pdf` — generate the Markdown first anyway, then convert.
  If a PDF skill is available in the environment (see available skills:
  `anthropic-skills:pdf` / Adobe PDF tools), use it for conversion
  instead of reinventing PDF generation by hand.
- `--executive` — executive summary only (`executive-summary.md`),
  without the full technical detail of each finding. Intended for
  non-technical stakeholders.

## Report sections (full)

Use `templates/engagement-report.md` if it exists; otherwise this
structure (and flag the content gap):

1. **Executive summary** — 1 page: what was tested, findings count by
   severity, the 1-3 most critical chains in non-technical language, and
   the main recommendation. This section is the same as what `--executive`
   produces on its own.
2. **Scope and methodology** — confirmed scope (from `scope.json`),
   engagement window, phases executed, known limitations (e.g. "brute
   force of credentials was not tested per engagement rules").
3. **Findings, ordered by severity** (critical → high → medium →
   low → info), each with:
   - ID, title, class (CWE), affected asset
   - Severity + CVSS 4.0 vector string, with each metric justified by
     what was verified; add CVSS 3.1 if the platform/client requires it
   - Description and root cause
   - Steps to reproduce, numbered
   - Evidence (reference or embed the request/response, with sensitive
     data redacted if the report will circulate beyond the authorized
     contact)
   - Demonstrated impact (never "could allow" without a PoC)
   - Concrete remediation
   - MITRE ATT&CK mapping (tactic + technique ID)
   - `evidence_tag` (Demonstrated/Inferred/Unproven) visible
4. **Attack chains** — each chain from `/quarry:chain` that passed
   `/quarry:validate`, with the full mechanism, the component findings
   (as references, not repeated in full), and combined impact.
5. **Coverage matrix** — from `CoverageTracker.summary()` and
   `get_gaps()`: what was tested, what was not, and why (scope, time, or
   technical limitation). This is as important as the findings — a
   report without declared gaps implies total coverage, which is almost
   never true.
6. **Framework mapping** — CVSS table per finding, aggregated MITRE
   ATT&CK table (which tactics/techniques the engagement covers as a
   whole), and if applicable, NIST CSF / OWASP Top 10
   (`references/frameworks/`).
7. **Recommendations** — prioritized by severity and business impact,
   not just by numerical CVSS (a `medium` that enables a critical chain
   takes priority over an isolated `high`).
8. **Appendices** — findings `KILLED` during validation (with reason,
   for transparency if the client asks why something flagged by a
   scanner doesn't appear), and the engagement phase history.

## Exact steps

1. Load `VALIDATED`/`REPORTED` findings and verified chains.
2. If `--executive`: generate only section 1, expanded to ~1-2 pages,
   and stop there.
3. If not: generate all sections in order, write
   `<audit_dir>/report/engagement-report.md`.
4. Transition each included finding from `VALIDATED` to `REPORTED`
   (`FindingsStore.update_status(id, FindingStatus.REPORTED)`).
5. If `--format pdf`: convert the Markdown to PDF (via available PDF
   skill), save alongside the `.md`.
6. Transition the engagement phase to `REPORTING` if it was at
   `VALIDATING`.
7. Ask the operator whether the engagement closes (`Phase.CLOSED`)
   after delivering the report, or stays open for a retest round —
   do not close automatically.

## Edge cases

- **Mix of validated and non-validated findings the operator wants to
  show anyway**: allow, but in a separate appendix with an explicit note
  that they did not pass the full validation pipeline.
- **Validated chain whose individual component findings are NOT
  validated** (the combination passed rebuttal, but a base finding
  stayed in `STALL`): this should not happen if `/quarry:validate` was
  run correctly on the chain; if it does, flag it as a state
  inconsistency and resolve before including the chain in the report.
- **Partial report mid-engagement** (operator requests a snapshot
  before finishing hunting): generate it, but clearly title it
  "Partial report — engagement in progress" and list which phases
  remain.
- **Real sensitive data in evidence** (PII, real credentials): redact
  in the report unless the recipient is exactly the authorized contact
  and the delivery format already accounts for this in the engagement
  rules.

## Expected output

- Path(s) of the generated file(s).
- Count of included findings by severity, and chain count.
- Coverage summary and declared gaps.
- If relevant `STALL`/`KILLED` findings remain, mention them even
  though they are not in the report body.
