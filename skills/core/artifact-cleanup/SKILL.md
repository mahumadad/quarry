---
name: artifact-cleanup
description: Remove test artifacts, temp files, and operator-generated payloads from the target and local workspace
domain: core
depends_on: [scope-discipline]
---

# Artifact Cleanup

Post-engagement cleanup of artifacts left during testing.

## Checklist

1. **Target-side cleanup** — Remove any uploaded shells, test files, planted
   payloads, or test accounts created during exploitation. Verify each
   removal with a follow-up request confirming 404/403.

2. **Local workspace** — Archive evidence artifacts to the custody-logged
   store (`engine/artifacts.py`). Remove transient files (screenshots of
   non-findings, raw scan output already parsed).

3. **Credential material** — Hand off to `credential-hygiene` for tokens,
   cookies, and API keys captured during testing.

4. **Verify nothing lingers** — Re-scan the target's known upload/temp
   paths to confirm no operator artifacts remain.

## Rules

- Never delete evidence artifacts — they go to the custody store, not the bin.
- Log every cleanup action in the custody chain.
- If a planted artifact cannot be removed (no delete access), document it
  as a residual risk in the closeout checklist.
