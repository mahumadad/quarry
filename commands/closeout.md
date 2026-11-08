---
name: quarry:closeout
description: Close engagement with final coverage summary and deliverable checklist
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:closeout — Formal engagement closure

Usage: `/quarry:closeout`

Launches `workflows/closeout.yaml`. The rule: an engagement is NOT finished
when the report is delivered — it is finished when the closeout is complete.

## Checklist it executes

1. **Artifact cleanup** — every uploaded file, created account, configured
   webhook, and deliberate state change is removed, delegated to the client,
   or documented as irreversible. No exceptions.
2. **Credential hygiene** — vault rotated/revoked, engagement tokens killed,
   no credentials outside the vault.
3. **Evidence seal** — final `CustodyLog.verify()` (must be INTACT),
   closure event, and bundle with SHA-256 manifest via `/quarry:deliver`.
4. **Data retention** — contractual destination for engagement data;
   destruction is recorded in custody as the last event. `knowledge.py`
   only retains anonymized techniques — verify.
5. **Debrief** — closing session with the client (walkthrough of criticals,
   gaps, next steps: retest / surface-watch / purple-team).

## Rules

- Every cleanup item requires removal evidence (request confirming
  404, disabled account, etc.) — "I deleted it" is not verification.
- If an artifact CANNOT be removed (data written without rollback), it stays
  in the report as such — the client must know.
- The closeout also has a time window: run it within the authorized time
  (timeguard), because the cleanup itself touches the target.
