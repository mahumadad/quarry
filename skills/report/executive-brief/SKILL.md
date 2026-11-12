---
name: executive-brief
description: >
  Produce the one-page, non-technical brief for C-level/board audiences: overall risk rating,
  the top 3 critical chains in plain language, and the headline remediation priorities, using
  `templates/executive-summary.md`. Use for `/quarry:report --executive`, or whenever the full
  technical report already exists and a standalone leadership-facing summary is needed
  separately. Do NOT use this in place of the full `report-writing` deliverable — this skill
  only produces the one-page synthesis, and per `executive-summary.md`'s own footer, the full
  technical report remains the source of truth on any discrepancy.
metadata:
  type: report
  phase: reporting
  tools: [findings.py, chain_engine.py]
depends_on: [report-writing]
feeds_into: []
---

## Signals

- `/quarry:report --executive` was invoked.
- The full `engagement-report.md` is finished and a separate leadership-facing one-pager is
  needed for distribution to people who won't read the technical sections.
- A mid-engagement checkpoint needs a short, accurate status for stakeholders without
  generating the full report.

## Prerequisites

- Either a finished `report-writing` output to summarize from, or (for an early checkpoint) at
  least the current `VALIDATED` findings/chains and coverage data — state clearly if this is a
  snapshot rather than a final brief.
- `templates/executive-summary.md` as the structural skeleton.
- The composite risk rating and Top 3 chains, consistent with what `framework-mapping` and
  `report-writing` already computed — this skill never recalculates them independently.

## Methodology

1. **Write this last, after the technical report (or current validated set) is final.** An
   executive brief written before the findings are locked risks promising a narrative the
   final technical content doesn't support.

2. **State the engagement overview in 2-3 plain-language sentences.** What was evaluated, with
   what objective, under what general methodology (e.g. "gray-box, simulating an attacker with
   a basic user account") — no jargon, no vuln-class names without a one-clause plain
   explanation if used at all.

3. **Fill the Key Metrics table** (count by severity, total findings, chain count) directly
   from the final validated set — these numbers must match the full report's Findings section
   exactly; a brief with different counts than the technical report is a credibility problem,
   not a simplification.

4. **Select the Top 3 critical chains by real-world risk, not raw severity count.** Per
   `executive-summary.md`'s own framing: "no es lo mismo el finding más severo que la cadena de
   mayor riesgo real" — rank by the combination of exploitation likelihood and business impact,
   using the validated chains from `chain-graph-walk`/`chain-analysis`, not just the three
   highest CVSS-scored standalone findings. If fewer than 3 validated chains exist, state that
   plainly rather than padding the list with standalone findings dressed up as chains.

5. **State the overall risk rating with a one-sentence justification** that a non-technical
   reader can act on — e.g. "Critical, because a demonstrated account-takeover chain requires
   no victim interaction and no prior authentication." The justification must trace to a
   specific validated chain/finding, not a general impression.

6. **List Immediate Actions as a short, urgent subset**, distinct from the full report's
   prioritized Recommendations list — these are the 1-3 things that should start before the
   reader finishes the document, not the complete remediation roadmap.

7. **State coverage in one line** (percentage of in-scope surface actively tested), pointing to
   the full report's Gaps section for detail rather than reproducing it here — the brief
   summarizes that a gap exists, the technical report explains which and why.

8. **Cross-check consistency against the full report before delivery.** Every number, chain
   name, and risk rating in the brief must match the full `engagement-report.md` exactly — this
   is a synthesis, not an independently-argued document.

## Validation gate

- [ ] Every metric (counts by severity, chain count, coverage %) matches the full technical
      report exactly.
- [ ] Top 3 chains are selected by combined likelihood × business impact, not by CVSS alone,
      and are genuinely validated chains (not re-labeled standalone findings) unless explicitly
      noted as fewer than 3 existing.
- [ ] The overall risk rating's one-sentence justification traces to a specific
      finding/chain ID.
- [ ] Document states plainly whether it's a final brief or a mid-engagement snapshot.
- [ ] No technical jargon appears without a plain-language gloss, consistent with the stated
      "Dirección / no técnica" audience.

## Gotchas

- The most common failure mode is a brief that reads more alarming or more reassuring than the
  full report supports — every sentence here must be traceable to something the technical
  sections actually say; this is the same anti-fabrication discipline as any finding, applied
  to the summary layer.
- Don't let "one page" pressure cut the Immediate Actions list down to vague generic advice
  ("improve security posture") — each immediate action should name what, specifically, needs to
  happen first, even in non-technical language.
- A mid-engagement snapshot brief must never be filed, titled, or distributed in a way that
  could be mistaken for the final deliverable — the project's cobertura/budget rules mean the
  picture can still change materially before close.
- If the full report has zero validated chains (only standalone findings), say so directly in
  the Top 3 section rather than forcing three items — an honest "no validated multi-finding
  chains this engagement" is more useful to leadership than a stretched narrative.
