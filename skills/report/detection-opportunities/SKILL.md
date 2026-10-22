---
name: detection-opportunities
description: >
  Purple-team reporting layer: for each demonstrated finding, document what telemetry
  SHOULD have fired (logs, alerts, detections) and map to ATT&CK data sources and
  Atomic Red Team tests. Use in the reporting phase of contracted pentests (not bug
  bounty) to turn findings into defensive value: the client learns not just what broke
  but why nobody noticed. Keywords: detection engineering, purple team, logging gaps,
  SIEM, sigma, atomic red team, ATT&CK data sources, alert coverage, blue team value.
  Do NOT use for bug bounty submissions (platforms don't consume detection advice) or
  as a substitute for the finding's technical content.
metadata:
  type: report
  phase: reporting
  mitre_attack: [T1562]
  tools: []
depends_on: [report-writing, framework-mapping]
feeds_into: [executive-brief]
chains_with: []
---

## Purpose

A pentest report that only says "we got in" tells the client they have
problems. The detection layer tells them WHERE their visibility failed — and
it's the difference between a report that gets shelved and one that drives a
detection-engineering backlog. One short section per demonstrated finding.

## What to document per finding

1. **Attack technique → ATT&CK data sources.** For the finding's mapped
   technique(s), name the data sources that would have observed it (per
   ATT&CK data components): e.g., SSRF → "Network Traffic: network connection
   creation from app server to link-local addresses"; password-spray →
   "Authentication Logs: failed/success ratio anomalies".
2. **Expected telemetry.** The concrete log/alert that SHOULD exist:
   which system (app logs, WAF, EDR, cloud audit logs — CloudTrail/Azure
   Activity Log/GCP Audit), which fields, which threshold or signature.
3. **Observed reality (when verifiable).** If the engagement included log
   access or a debrief with the SOC: did anything fire? If unknown, say
   "not verified — recommend replay during purple-team session". Never claim
   "no detection exists" without having seen the client's telemetry.
4. **Detection idea, not a product.** One concrete, implementable detection:
   a Sigma-style rule sketch, a KQL/SPL query fragment, or a metric + alert
   threshold. Tied to the exact PoC behavior from this engagement.
5. **Replay test.** Reference the matching Atomic Red Team test
   (atomics are organized by ATT&CK technique ID — e.g., T1190 has web-shell
   and exploit atomics) or provide the minimal replay steps, so the blue team
   can validate the new detection against a safe reproduction.

## Where it lives in deliverables

- Per-finding: "Detection opportunities" subsection after Remediation in
  finding-template.md.
- Engagement-level: a coverage table in engagement-report.md — finding ×
  data-source × detection-status (observed / expected-missing / unverified) —
  which doubles as a logging-maturity snapshot for the executive summary.
- Custody appendix unchanged: detection content is advisory, evidence rules
  still govern the finding itself.

## Gotchas

- **Don't fabricate the client's stack.** If you don't know their SIEM/EDR,
  write the detection idea tool-agnostic (data source + logic) and mark
  implementation as client-specific.
- **Detection ≠ prevention.** Note when the right fix is a control change,
  and the detection is only a compensating measure — never invert them.
- **Verbosity risk:** one tight block per finding. If everything gets a
  detection paragraph, none of them get read — prioritize by severity and by
  how stealthy the technique actually was.
- **Bounty mode: skip entirely.** Hunt-mode severity gating (findings.py)
  already excludes this skill from bounty engagements via the router.
- Claiming a specific product "would have caught this" without testing it is
  vendor speculation — phrase as detection ideas, not product claims.

## Chain Anchors (report-level)

1. Multiple findings share one data-source gap (e.g., no egress monitoring
   enabled SSRF + exfil + C2-like callbacks) → escalate to a structural
   recommendation in the executive brief: one logging fix kills N findings'
   stealth.
2. Zero detections expected across the whole engagement → that absence is
   itself a headline finding for the executive summary ("dwell time would
   have been unlimited").
