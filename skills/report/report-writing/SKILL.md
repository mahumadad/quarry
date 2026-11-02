---
name: report-writing
description: >
  Assemble the full engagement deliverable — executive summary, findings by severity, chains,
  coverage matrix, gaps, recommendations — from VALIDATED material only, using
  `templates/engagement-report.md` and `templates/executive-summary.md`. Use once
  `/quarry:validate` has produced at least one `VALIDATED` finding and the engagement is ready for
  `/quarry:report`. Do NOT use this to decide whether a finding is reportable — that decision
  already happened in `finding-validation`/`triage-gate`/rebuttal; this skill only translates
  and synthesizes what already passed. Do NOT use for the one-page client-facing brief alone —
  that's executive-brief; this skill produces the full technical deliverable (which also
  contains an executive summary section).
metadata:
  type: report
  phase: reporting
  tools: [coverage.py, findings.py, chain_engine.py]
depends_on: [triage-gate, chain-graph-walk]
feeds_into: [framework-mapping, executive-brief]
---

## Signals

- `/quarry:report` was invoked and at least one finding has status `VALIDATED` or `REPORTED`
  (`FindingsStore.list_by_status(FindingStatus.VALIDATED)`).
- The engagement is transitioning from `VALIDATING` to `REPORTING` phase.
- A partial/interim report is requested mid-engagement — same methodology, explicitly titled
  as a snapshot.

## Prerequisites

- At least one `VALIDATED` finding. If none exist, stop and surface that `/quarry:validate` hasn't
  produced anything reportable yet — don't manufacture a findings report from `DETECTED`/
  `CONFIRMED`/`STALL` items.
- `templates/engagement-report.md` and `templates/executive-summary.md` as the structural
  skeletons.
- Coverage data from `CoverageTracker.summary()`/`get_gaps()`, and the engagement's scope/RoE
  record for the Scope section.
- Validated chains from `/quarry:chain` + `/quarry:validate`, each with `chain-report.md`-shaped detail.

## Methodology

1. **Inventory eligible material only.** Pull every finding at `VALIDATED`/`REPORTED` and every
   chain whose combined claim independently passed `finding-validation`'s four gates (not
   inherited from its components). Anything still `DETECTED`/`CONFIRMED`/`STALL`/`KILLED` does
   not enter the main body — `KILLED` items may get a one-line appendix note for transparency,
   per `commands/report.md`.

2. **Fill the Scope and Methodology sections first**, from the confirmed `scope.txt`/RoE record
   and the actual phases executed — not from the original plan if execution diverged from it.

3. **Write the Findings section, ordered critical → high → medium → low → info.** For each
   finding, carry forward exactly what `finding-validation` produced: CVSS vector with
   per-metric justification, MITRE mapping, evidence tag, steps to reproduce. Never recompute
   or soften these here — this skill translates, it doesn't re-score. Use
   `templates/finding-template.md`'s shape for each entry or its full-file reference in an
   appendix.

4. **Write the Chains section** from each validated `chain-report.md`, preserving the chain's
   stated overall confidence (minimum of its edges, per `chain-graph-walk`/`chain-analysis`) and
   explicitly flagging any edge still `theoretical` rather than presenting the whole chain as
   uniformly demonstrated.

5. **Build the Coverage Matrix** from `CoverageTracker.summary()`: vuln class × asset, each
   cell `Tested — Clean`, `Tested — Finding(s): {{ids}}`, `Not tested — {{reason}}`, or
   `N/A — {{reason}}`. An engagement with no declared gaps is a red flag for this step, not a
   sign of thoroughness — re-check that gaps were actually tracked during hunting.

6. **Write the Gaps section as its own first-class content**, not an afterthought — every "not
   tested" cell in the coverage matrix gets a one-line reason (scope, time, technical blocker,
   RoE restriction) and an estimated residual risk. A report with findings but no gaps section
   implies total coverage, which is almost never true.

7. **Write Recommendations prioritized by real risk reduction**, not raw CVSS ranking — a
   medium-severity finding that is the single enabling link in a validated critical chain
   outranks an isolated high with no chain dependency. Tie each recommendation explicitly to
   the finding IDs it addresses.

8. **Hand off framework mapping and the executive summary** — `framework-mapping` produces the
   MITRE/NIST/OWASP sections, and the final executive summary is written last (see
   `executive-brief`), after every technical section is final, so it reflects what's actually
   in the body rather than being written from intention.

9. **Assemble into `templates/engagement-report.md`'s structure**, write to
   `<audit_dir>/report/engagement-report.md`, and transition every included finding from
   `VALIDATED` to `REPORTED`.

10. **Redact sensitive data** (real PII, live credentials) per the RoE's data-handling clause
    before the report leaves the engagement's secure channel, unless the exact authorized
    recipient and format already account for unredacted delivery.

## Validation gate

- [ ] No finding in the main Findings section lacks a `VALIDATED`/`REPORTED` status.
- [ ] Every finding's CVSS/MITRE/evidence-tag in the report matches exactly what
      `finding-validation` produced — no re-scoring, no tag upgrades for narrative flow.
- [ ] Coverage Matrix and Gaps sections are both present and non-trivial (a report with zero
      declared gaps has been double-checked, not just assumed complete).
- [ ] Recommendations reference specific finding/chain IDs, not generic best-practice text
      disconnected from what was found.
- [ ] Sensitive data is redacted per the RoE unless the delivery context explicitly allows
      otherwise.

## Gotchas

- Never include a finding that didn't get `ACCEPTED`/`VALIDATED` just because the operator is
  confident it's real — route the disagreement back to `finding-validation`/rebuttal, don't
  resolve it by writing it into the deliverable.
- A validated chain's narrative must not borrow stronger evidence language than its weakest
  edge supports — the chain's overall confidence is the minimum across edges, never the
  average or the strongest.
- Writing the executive summary before the technical sections are final is the most common
  cause of a report that oversells itself — always write it last, from what's actually there.
- A partial/interim report must say so in the title and list which phases are still pending —
  never let a snapshot read as a final deliverable.
