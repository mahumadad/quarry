---
name: framework-mapping
description: >
  Map every validated finding and chain to MITRE ATT&CK (tactic + technique ID), NIST CSF
  categories, and OWASP Top 10, then build the composite ATT&CK heatmap showing which
  tactics/techniques the engagement actually demonstrated coverage for. Use while assembling
  `report-writing`'s framework-mapping section, after findings/chains are final (no more
  additions expected). Do NOT use this to invent a mapping for completeness — a tactic with no
  demonstrated technique is reported as "not attempted/not applicable," never filled in to make
  the heatmap look fuller than the engagement actually was.
metadata:
  type: report
  phase: reporting
  tools: [findings.py, mitre-attack-navigator]
depends_on: [triage-gate]
feeds_into: [report-writing, executive-brief]
---

## Signals

- `report-writing` has a final (post-rebuttal) list of validated findings/chains and needs the
  composite framework sections.
- The client's compliance/risk team specifically asked for NIST CSF or OWASP Top 10 mapping
  alongside the technical findings.
- Building the engagement's MITRE ATT&CK heatmap for the executive summary's Top 3 chains or
  the full report's appendix.

## Prerequisites

- Final validated findings/chains — each finding already carries an individual MITRE mapping
  from `finding-validation` (tactic + technique ID, chosen for what was actually executed).
  This skill aggregates those, it does not invent new per-finding mappings.
- MITRE ATT&CK tactic/technique reference (current matrix) for technique-ID lookups and to
  confirm IDs haven't been deprecated/renumbered since a finding was first mapped.

## Methodology

1. **Pull every individual MITRE mapping already attached to each validated finding.** Do not
   recompute these — `finding-validation` already chose the technique that matches what was
   actually executed, not the broadest technique the vuln class could theoretically map to.

2. **Build the composite ATT&CK view across the whole engagement.** Group by tactic
   (Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense
   Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact)
   and list every distinct technique ID actually demonstrated under it. A tactic with no
   demonstrated technique is listed as empty/not-applicable in the heatmap, never populated
   with a plausible-but-unexecuted technique just to fill the cell.

3. **For chains specifically, map the end-to-end sequence, not just each link's own tactic.**
   A chain typically traverses multiple tactics (e.g. Initial Access → Privilege Escalation →
   Collection) — record the full tactic sequence for the chain narrative in addition to each
   component finding's individual mapping, since the sequence itself is informative (it shows
   the client's actual kill-chain exposure, not just isolated technique hits).

4. **Render the heatmap** as the table from `templates/engagement-report.md`'s MITRE ATT&CK
   Heatmap section: one row per tactic, cell listing the technique IDs demonstrated under it.
   Cross-reference against `pivot-graph.md`'s node sequence for any validated multi-hop chain to
   make sure the heatmap's technique list for that chain matches the graph's actual edges.

5. **Map to NIST CSF categories** based on what each finding reveals about an actual control
   gap (Identify/Protect/Detect/Respond/Recover), not a mechanical vuln-class-to-category
   lookup table. E.g. a finding that succeeded because no anomaly detection flagged mass
   enumeration maps to Detect, not just Protect, even though the root vulnerability is an
   access-control issue.

6. **Map to OWASP Top 10** (current revision) per finding, for readers who expect that specific
   framing — this is usually the easiest mapping since most hunt-* skills target OWASP-named
   categories directly, but verify the current revision's category numbering hasn't shifted
   from what the finding's original classification assumed.

7. **Flag coverage gaps the heatmap itself reveals.** A tactic with zero demonstrated technique
   is cross-checked against the Coverage Matrix — is it empty because it genuinely wasn't
   relevant to this engagement's scope (e.g. no Lateral Movement opportunity existed), or
   because it wasn't tested (a real gap)? State which, explicitly, next to the empty cell.

## Validation gate

- [ ] Every technique ID in the composite heatmap traces to at least one specific finding/chain
      ID that actually demonstrated it — no technique appears from aggregation logic alone.
- [ ] Every tactic row is populated or explicitly marked not-attempted/not-applicable with a
      reason — no blank cells without explanation.
- [ ] NIST CSF and OWASP mappings reflect the actual control gap/category revision, not a
      stale or mechanical lookup.
- [ ] Chain mappings include the full tactic sequence, not just a single tactic per chain.

## Gotchas

- The single most common inflation in pentest reports is a heatmap that implies broader
  coverage than was tested — always distinguish "not applicable to this target" from "not
  tested" in the gap notes, since they mean very different things to a client prioritizing
  their own testing budget next time.
- MITRE ATT&CK technique IDs get revised/retired between matrix versions — if a finding was
  mapped months ago in a prior engagement and reused via memory, re-verify the ID is still
  current before publishing.
- Don't let a chain's "sounds like Lateral Movement" narrative smuggle in a Lateral Movement
  tactic tag when the actual demonstrated techniques were all Initial Access + Privilege
  Escalation on a single host — map what was shown, not what the story suggests.
- OWASP Top 10 categories shift definitions between revisions (e.g. what used to be "A5 -
  Broken Access Control" numbering changes) — confirm against the revision the client expects
  before publishing, not from memory of an older version.
