---
name: report-qc
description: >
  Adversarial quality control of the final report BEFORE delivery. Use as the last
  gate of the reporting phase: verify every claim in the report traces to evidence,
  numbers are internally consistent, severities are justified, and nothing violating
  the anti-fabrication or never-submit rules slipped through. The report is the only
  thing the client keeps — this is the last chance to catch it lying.
  Keywords: report review, QC, consistency check, claim verification, pre-delivery
  gate, executive summary consistency, peer review.
  Do NOT use as a substitute for finding-level validation (that already happened) —
  this checks the DOCUMENT, not the vulnerabilities.
metadata:
  type: report
  phase: reporting
  mitre_attack: []
  tools: []
depends_on: [report-writing, evidence-hygiene]
feeds_into: [executive-brief]
chains_with: []
---

## Purpose

Findings were validated individually; the report can still lie in the
aggregate: an executive summary that overstates, a coverage matrix that
claims testing that didn't happen, a severity that drifted between the
finding body and the findings table. This gate reviews the report as an
adversary — "if I were the client's skeptical CISO, where would this
document embarrass us?"

## QC protocol (every item verifiable, every failure blocking)

1. **Claim → evidence trace.** For EVERY finding in the findings table:
   open its finding file; confirm evidence exists, hashes verify
   (`FindingsStore.verify_evidence_integrity`), and the stated impact is
   exactly what the evidence shows — no more, no less. Any "could lead to"
   phrasing in a Demonstrated finding without demonstrated next step →
   rewrite or downgrade tag.

2. **Internal consistency sweep:**
   - Finding count/severities in executive summary == findings table ==
     findings store summary.
   - CVSS vector strings parse and match their scores (recompute).
   - Status column: nothing below VALIDATED appears as a finding (leads
     belong in the leads-appendix, clearly labeled).
   - Chain CVSS ≥ max(member CVSS) with justification, never lower silently.

3. **Never-submit audit.** Cross-check the findings table against
   `references/never-submit.md` one final time — a self-XSS or
   missing-headers "finding" in a delivered report damages credibility more
   than a missed bug.

4. **Coverage honesty.** Read the Coverage Matrix against the brain's
   exhaustion tracking: every `Tested — Clean` cell must correspond to
   actual recorded testing; every gap must appear in the Gaps section.
   Overstated coverage is the most common report lie.

5. **Evidence hygiene in the document.** No real credentials, session
   tokens, or third-party PII in the report body (redact; the raw evidence
   in the appendix carries them only if the delivery channel is the agreed
   encrypted one). Timestamps present on all evidence references.

6. **Custody attestation.** `CustodyLog.verify()` result quoted in the
   appendix MUST be ÍNTEGRA at emission time. A broken chain blocks delivery.

7. **Readability pass (operator).** One human reads the executive summary
   cold: could a non-technical director state the actual risk after reading
   it? If the answer is "it says we found 14 vulnerabilities", rewrite — the
   summary must state RISK (what breaks, how bad, what to do first), not
   counts.

## Output

- QC checklist with pass/fail per item, stored with the engagement artifacts.
- Any FAIL blocks delivery until fixed and re-checked (record the fix).
- Custody event: `report_qc` with the checklist result, actor: operator.

## Gotchas

- QC is adversarial, not editorial — "sounds good" is not a check. Each item
  has a mechanical verification.
- Beware summary drift after last-minute finding changes: re-run items 1–2
  if ANY finding changed after the first QC pass.
- The leads-appendix exists so excluded work is visible; moving a weak
  finding INTO the findings table to look productive is exactly what B1–B7
  existed to prevent — QC enforces it again here.
