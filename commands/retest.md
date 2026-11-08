---
name: quarry:retest
description: Run a remediation verification engagement against a prior report
argument-hint: "<original_engagement_dir>"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:retest — Remediation verification engagement

Usage: `/quarry:retest <original_engagement_dir>`

## What it does

Launches the `retest.yaml` workflow against findings from a prior engagement:
the client applied fixes and we need to verify the exploits are dead.

## Flow

1. **Load the original engagement**: findings, PoCs (steps-to-reproduce),
   target snapshot (engine/checkpoint.py / target_diff).
2. **Baseline diff** (`engine/target_diff.py`): what changed on the target
   since the original scan. Unexpected changes (new paths, new services)
   are reported to the operator BEFORE re-testing — they may be unauthorized
   new scope.
3. **Cold-session re-exploit** for each finding (re-exploit-agent):
   - fresh cookie jar, fresh credentials from the vault,
   - execute the EXACT PoC from the report,
   - classify: FIXED / PARTIAL / NOT_FIXED / REGRESSED (see retest.yaml).
4. **Variant sweep**: for findings whose pattern had siblings
   (variant-analysis), sweep unreported locations — an instance fix without
   a pattern fix is the most common false "fix".
5. **Retest report**: finding × status × new evidence table. No new
   hunting — new surface requires a new engagement with its own scope.

## Rules

- Every re-test produces new evidence: requests/responses from the re-test are
  saved with timestamp and hash like any evidence (custody log).
- PARTIAL and NOT_FIXED reopen the finding with re-test evidence —
  never use "the client said they fixed it" as closure.
- FIXED also requires evidence: capture of the new control working
  (the 403, the validation), not just "the payload no longer works".
- If the target changed structurally (major version, rewrite), declare it:
  a retest on an app different from the one audited has limited validity —
  recommend a new engagement.

## Example

```
/quarry:retest engagements/acme-2026-09
```
