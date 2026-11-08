---
name: quarry:export
description: Export findings to machine-readable formats (SARIF, JSON, CSV)
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:export — Export findings to machine-readable formats

Usage: `/quarry:export [sarif|json|csv] [output_path] [--all]`

## What it does

1. Reads the FindingsStore from the current engagement (`.pentest-state/findings.json`).
2. By default exports ONLY findings in VALIDATED or REPORTED status —
   leads, hypotheses, and KILLED findings do not leave the pipeline
   (anti-fabrication rule applied to exports).
3. `--all` includes the entire store (useful for internal audit, NEVER for
   client delivery).
4. Generates the file via `engine/exporters.py`:
   - **sarif** — SARIF 2.1.0 for GitHub/GitLab code scanning, Defender,
     any SARIF consumer. Includes CVSS 4.0, EPSS, KEV in properties.
   - **json** — one flat object per finding, ready for ticket creation
     (Jira/Linear/ServiceNow) or automation feeds.
   - **csv** — spreadsheet triage.
5. Records the export in the custody log (`engine/custody.py`): format,
   path, finding count, timestamp — the report attests what was delivered.

## Rules

- Every export is a custody event — no exceptions.
- A SARIF export is also an artifact for the fix→retest loop: the client
  uploads it to code scanning, fixes, and `/quarry:retest` verifies.
- EPSS/KEV fields are enriched before export if there are findings with CVEs
  (see `references/cvss4-epss-kev.md`).
- Verify the exported finding count against `/quarry:findings` — an
  export of 0 findings when there are validated ones is a bug, not a result.

## Examples

```
/quarry:export sarif outputs/eng-2026-10/findings.sarif
/quarry:export json outputs/eng-2026-10/tickets.json
/quarry:export csv outputs/eng-2026-10/triage.csv --all
```
