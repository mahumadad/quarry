# Engagement Report — {{engagement_name}}

**Client:** {{client_name}}
**Start date:** {{start_date}}
**End date:** {{end_date}}
**Engagement type:** {{engagement_type}} (web app / API / cloud / AD / mobile / red team)
**Team:** {{team_members}}
**Document classification:** {{classification}} (e.g. Confidential — client only)

---

## Executive Summary

{{executive_summary}}

See also `executive-summary.md` for the one-page version aimed at
non-technical stakeholders. This section must be consistent with that one,
but with more detail: what was tested, what was found, what the real risk
is (not just finding counts), and what should happen first.

**Overall risk posture:** {{overall_risk_posture}} (e.g. Critical / High / Medium / Low)

## Scope

### In scope

| Asset | Type | Notes |
|---|---|---|
| {{scope_asset_1}} | {{scope_type_1}} | {{scope_notes_1}} |
| {{scope_asset_2}} | {{scope_type_2}} | {{scope_notes_2}} |

### Out of scope

| Asset | Exclusion reason |
|---|---|
| {{oos_asset_1}} | {{oos_reason_1}} |

### Rules of engagement

- **Testing window:** {{testing_window}}
- **Excluded techniques:** {{excluded_techniques}} (e.g. volumetric DoS, employee phishing without separate authorization)
- **Emergency contact:** {{emergency_contact}}
- **Authorization:** {{authorization_reference}} (document/email authorizing the engagement)

## Methodology

{{methodology_summary}}

Phases executed: {{phases_executed}} (recon → mapping → hunting → chaining →
adversarial validation → reporting). For each phase, reference what coverage
was achieved — granular detail goes in the Coverage Matrix below.

**Tools used:** {{tools_used}}

## Target Card

{{target_card_embed_or_ref}}

Embed the complete target card (see `target-card.md`) for the primary
target here, or a link/reference if the engagement covered multiple targets
with separate cards.

## Findings (ordered by severity)

| ID | Title | CVSS | Severity | Status | CWE |
|---|---|---|---|---|---|
| {{finding_id_1}} | {{finding_title_1}} | {{cvss_1}} | Critical | {{status_1}} | {{cwe_1}} |
| {{finding_id_2}} | {{finding_title_2}} | {{cvss_2}} | High | {{status_2}} | {{cwe_2}} |
| {{finding_id_n}} | {{finding_title_n}} | {{cvss_n}} | {{severity_n}} | {{status_n}} | {{cwe_n}} |

Each finding referenced here has its full write-up in `finding-template.md`
format in the Appendix or as a separate file.

## Chains

| Chain ID | Combined findings | Combined impact | Combined CVSS |
|---|---|---|---|
| {{chain_id_1}} | {{chain_findings_1}} | {{chain_impact_1}} | {{chain_cvss_1}} |
| {{chain_id_2}} | {{chain_findings_2}} | {{chain_impact_2}} | {{chain_cvss_2}} |

Each chain referenced here has its full write-up in `chain-report.md` format.

## Coverage Matrix

Vulnerability class × asset matrix — what was explicitly tested, what
yielded results, and what was left untested (and why).

| Vuln class | {{asset_1}} | {{asset_2}} | {{asset_n}} |
|---|---|---|---|
| SQLi | {{coverage_sqli_asset1}} | {{coverage_sqli_asset2}} | {{coverage_sqli_assetn}} |
| XSS | {{coverage_xss_asset1}} | {{coverage_xss_asset2}} | {{coverage_xss_assetn}} |
| SSRF | {{coverage_ssrf_asset1}} | {{coverage_ssrf_asset2}} | {{coverage_ssrf_assetn}} |
| IDOR/BAC | {{coverage_idor_asset1}} | {{coverage_idor_asset2}} | {{coverage_idor_assetn}} |
| Auth bypass | {{coverage_auth_asset1}} | {{coverage_auth_asset2}} | {{coverage_auth_assetn}} |
| ... | ... | ... | ... |

Cell convention: `Tested — Clean`, `Tested — Finding(s): {{ids}}`,
`Not tested — {{reason}}`, `N/A — {{reason}}`.

## Gaps

{{gaps_summary}}

Explicitly list what was NOT tested, and why: out of scope, time
constraint, required credentials not provided, required destructive action
without separate authorization, etc. This section is as important as the
findings — an unreported gap gives the client a false sense of security.

| Gap | Reason | Estimated residual risk |
|---|---|---|
| {{gap_1}} | {{gap_reason_1}} | {{gap_risk_1}} |
| {{gap_2}} | {{gap_reason_2}} | {{gap_risk_2}} |

## Recommendations

Prioritized by real risk reduction, not just individual CVSS score (a
medium-severity chain that is trivial to exploit may take priority over an
isolated critical finding that requires unlikely preconditions).

1. **{{recommendation_1}}** — addresses: {{recommendation_1_findings}}
2. **{{recommendation_2}}** — addresses: {{recommendation_2_findings}}
3. **{{recommendation_3}}** — addresses: {{recommendation_3_findings}}

### Structural recommendations (beyond individual findings)

{{structural_recommendations}}

## Detection Coverage (purple team — contracted engagements)

> See `skills/report/detection-opportunities`. Omit this section in bug
> bounty mode (platforms do not consume detection advice).

Finding × data source × detection status table — serves as a snapshot
of the client's logging maturity:

| Finding | ATT&CK Data Source | Expected telemetry | Status |
|---|---|---|---|
| {{finding_id_1}} | {{ds_1}} | {{telemetry_1}} | {{detected_status_1}} |
| {{finding_id_2}} | {{ds_2}} | {{telemetry_2}} | {{detected_status_2}} |

Status convention: `Detected`, `Expected-absent`, `Not verified`
(never assert absence without having seen the client's telemetry).

**Structural visibility gaps:** {{detection_structural_gaps}}
(a single gap — e.g. no egress monitoring — often explains the stealth of N
findings; that gap is a headline recommendation for the executive summary)

## MITRE ATT&CK Heatmap

Techniques observed during the engagement, mapped to tactics.

| Tactic | Observed techniques |
|---|---|
| Reconnaissance | {{tactic_recon_techniques}} |
| Initial Access | {{tactic_initial_access_techniques}} |
| Execution | {{tactic_execution_techniques}} |
| Persistence | {{tactic_persistence_techniques}} |
| Privilege Escalation | {{tactic_privesc_techniques}} |
| Defense Evasion | {{tactic_evasion_techniques}} |
| Credential Access | {{tactic_credaccess_techniques}} |
| Discovery | {{tactic_discovery_techniques}} |
| Lateral Movement | {{tactic_lateral_techniques}} |
| Collection | {{tactic_collection_techniques}} |
| Exfiltration | {{tactic_exfil_techniques}} |
| Impact | {{tactic_impact_techniques}} |

## Appendix (raw evidence)

- {{appendix_item_1}} — {{appendix_item_1_path}}
- {{appendix_item_2}} — {{appendix_item_2_path}}

Include: raw tool outputs (nmap -oX, nuclei -json, etc.), relevant traffic
captures, complete discovered endpoint listings, testing session logs with
timestamps.

### Chain of custody

> Generated from `engine/custody.py` → `CustodyLog.attestation_block()`.

- Registered events: {{custody_entries}}
- Chain integrity: {{custody_integrity}} (INTACT / BROKEN — verify with
  `CustodyLog.verify()` before emitting the report)
- Head hash (SHA-256): `{{custody_head_hash}}`
- Log: `.pentest-state/custody.jsonl` (append-only, hash-chained)
- Exports emitted: {{custody_exports}} (format, path, date — what was
  delivered to the client and when)

### Machine-readable artifacts

| Format | Path | Usage |
|---|---|---|
| SARIF | {{sarif_path}} | GitHub/GitLab code scanning (`/quarry:export sarif`) |
| JSON | {{json_path}} | Ticketing / automation |
| CSV | {{csv_path}} | Spreadsheet triage |

---

**Report prepared by:** {{report_author}}
**Report date:** {{report_date}}
**Version:** {{report_version}}
