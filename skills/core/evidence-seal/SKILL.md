---
name: evidence-seal
description: Finalize and seal the custody chain — no further evidence modifications after this step
domain: core
depends_on: [finding-discipline]
---

# Evidence Seal

Lock the evidence chain for the engagement.

## Process

1. **Integrity check** — Verify the custody chain (`engine/custody.py`):
   every entry's hash links to the previous one, no gaps, no tampering.

2. **Evidence completeness** — For every finding with status VALIDATED or
   REPORTED, confirm that at least one artifact exists in the store and
   its SHA-256 matches the custody record.

3. **Seal entry** — Append a `seal` event to the custody log with:
   - Total artifact count
   - Total finding count by status
   - Chain integrity: pass/fail
   - Operator alias
   - Timestamp (UTC)

4. **Export** — Generate `custody-chain-sealed.json` with the full log
   for inclusion in the deliverable bundle.

## Rules

- After sealing, no new evidence may be added without breaking the seal
  (which requires a new seal event explaining why).
- The seal is locally tamper-evident, not cryptographically attestable
  to third parties (see I9 in TODO-AUDIT.md for future improvements).
