---
name: finding-discipline
description: >
  Evidence and quality standards for every finding before it goes in a report: the
  Demonstrated/Inferred/Unproven tagging system, what counts as a valid PoC, and how to
  justify a CVSS score. Use whenever a potential vulnerability is identified and before
  writing it up — this is the gate between "I think I found something" and "this is a
  reportable finding." Do NOT use for recon/scanning technique — use the relevant recon
  or hunt skill for that; this skill only governs how findings are documented and scored.
metadata:
  type: core
  phase: validating
  tools: [curl, burpsuite, cvss-calculator]
depends_on: [engagement-flow]
feeds_into: []
---

## Signals

- A scan, manual test, or tool flags a potential vulnerability.
- About to write a finding into a report draft.
- Deciding severity/CVSS for something already confirmed.
- Reviewing someone else's draft findings before they ship.

## Prerequisites

- The finding originates from in-scope testing (`scope-discipline` already cleared).

## Evidence tiers

Every finding gets exactly one tag, chosen by the strictest standard it meets:

- **Demonstrated** — you personally triggered the vulnerable behavior against the live
  target and captured proof (response showing the impact, not just the request). This is
  the only tier that supports a full, unqualified CVSS score and an "impact" write-up stated
  as fact.
- **Inferred** — strong circumstantial evidence (version banner matching a known CVE,
  behavior consistent with a vuln class, error message indicating a flaw) but you did not
  trigger the actual impact (e.g. found a SQLi-indicative error but didn't exfiltrate data,
  or found an outdated library but didn't build/run the matching exploit). Report with
  explicit "not exploited; inferred from X" language and a CVSS score caveated as
  "if confirmed."
- **Unproven** — a scanner/tool flagged it with no independent confirmation (default nikto/
  nuclei/nessus output, unconfirmed). Report only as a low-confidence note in an appendix,
  never as a numbered finding with a CVSS score, unless and until it's escalated to
  Inferred or Demonstrated.

Never let a finding's write-up imply a stronger tier than its actual evidence. "Appears to
allow X" belongs to Inferred language even if the formatted finding title sounds confident.

## Methodology

1. Capture raw evidence at the moment of discovery, before moving on:
   ```bash
   curl -i -s -X POST https://target/api/reset -d '{"user_id":1337}' -H "Authorization: Bearer $LOW_PRIV_TOKEN" > evidence/idor-001-request.txt
   ```
   Save full request + full response, not a screenshot cropped to "the interesting part."
2. For anything claimed as Demonstrated, write a minimal, reproducible PoC: exact request
   (curl/HTTPie), exact preconditions (account type, auth token scope, starting state),
   and the exact observable difference that proves impact (returned another user's data,
   executed a command, escalated a role). A PoC that only a specific session/token can
   reproduce is not yet "reproducible" — note that limitation explicitly.
3. Re-run the PoC clean right before reporting (see `engagement-flow`'s VALIDATING phase) —
   session state, caching, or a since-patched issue can make a stale PoC misleading.
   ```bash
   # re-run from a fresh, unauthenticated shell/session to rule out leftover state
   curl -i -s https://target/api/export/1 > evidence/idor-001-retest.txt
   diff evidence/idor-001-request.txt evidence/idor-001-retest.txt
   ```
4. Score CVSS using the official calculator methodology, and write out the vector string
   and the reasoning for each metric — not just the final number:
   ```
   CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
   AV:N  — reachable over the internet, confirmed via direct curl from outside the network
   AC:L  — no special conditions beyond a valid low-priv token
   PR:L  — requires authentication as any user (tested with a low-privilege account)
   C:H   — returned full PII of an arbitrary user (demonstrated, see evidence/idor-001)
   ```
   Every metric choice should trace to something observed, not a guess at worst case.
5. Attach exact version/commit/timestamp info for anything environment-dependent (the
   finding may be patched by the time the report is read).
6. Separate the finding (what's wrong) from the recommendation (how to fix it) — don't
   let a specific fix suggestion stand in for the actual technical root cause.
7. Map the finding to MITRE ATT&CK (tactic + technique ID, e.g. `T1190 — Exploit Public-
   Facing Application` under `Initial Access`) based on what was actually demonstrated,
   not the broadest technique the vuln class could theoretically map to.
8. Never report a finding from version/CVE-matching alone — a banner or package version
   matching a public CVE is Inferred at best until you trigger the actual behavior; see
   the project's anti-fabrication rule (CLAUDE.md) which is stricter than this skill alone
   and takes precedence.

## Tooling

`curl -i` (always capture full headers), request/response logging via Burp Suite's logger
or `mitmproxy`, a CVSS 4.0 calculator (official FIRST.org calculator or offline equivalent),
`diff` for before/after comparisons on retests.

## Validation gate

Before a finding goes into the report:
- [ ] Tagged Demonstrated / Inferred / Unproven, and the write-up language matches the tag.
- [ ] Raw evidence (full request+response or equivalent) saved, not just a summary.
- [ ] If Demonstrated: PoC re-run clean immediately before writing the final report.
- [ ] CVSS vector string present with per-metric justification, not just a bare score.
- [ ] Finding and recommendation are in separate sections.

## Gotchas

- Scanner output dressed up as a confirmed finding is the single most common quality failure
  in pentest reports — a nikto/nuclei hit is Unproven until independently reproduced.
- CVSS inflation: a real but low-impact issue (e.g. verbose error message) scored as High
  because "it could theoretically lead to..." — score what you demonstrated, not the worst
  hypothetical chain.
- PoCs that only work with a specific, soon-to-expire session token look reproducible to you
  but won't be to the client's remediation team — state preconditions explicitly.
- Don't silently downgrade an uncomfortable finding to Unproven to avoid conflict with the
  client — the tier reflects evidence quality only.
