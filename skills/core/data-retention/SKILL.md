---
name: data-retention
description: Apply the engagement's data retention policy — archive, redact, or destroy per contractual terms
domain: core
depends_on: [scope-discipline, evidence-seal]
---

# Data Retention

Apply retention policy after evidence sealing.

## Process

1. **Read retention terms** — Check `scope.json` for `retention_days` and
   `retention_policy` (archive / redact / destroy). Default: archive for
   90 days, then offer destruction.

2. **Classify data** —
   - **Keep:** Sealed custody chain, final report, finding summaries
   - **Redact:** Raw HTTP responses containing PII, database dumps,
     credential material (already handled by credential-hygiene)
   - **Destroy:** Temporary scan output, working notes, draft reports

3. **Execute** —
   - Archive: compress engagement directory, store with sealed chain
   - Redact: replace sensitive values with `[REDACTED]` in archived copies
   - Destroy: secure-delete (`shred` or platform equivalent) working files

4. **Document** — Log retention actions in the closeout checklist with
   what was kept, redacted, and destroyed.

## Rules

- Never destroy the sealed custody chain or final report.
- Retention periods are contractual — follow the client's terms, not defaults.
- Log all destruction actions before executing them.
