# Verdict → FindingStatus Mapping

Canonical mapping between rebuttal verdicts and the `FindingStatus` enum
in `engine/findings.py`.

## Rebuttal verdicts

The finding-checker agent (`agents/finding-checker.md`) and the
seven-question-gate (`references/seven-question-gate.md`) produce a
verdict for each finding they review. The verdict drives the next
status transition.

| Verdict    | Meaning                                  | FindingStatus transition                  | Notes |
|------------|------------------------------------------|-------------------------------------------|-------|
| `ACCEPTED` | Evidence and reasoning hold up           | Current → `VALIDATED`                     | Evidence gate must pass: `evidence != []`, `evidence_tag != "unproven"`, `steps_to_reproduce >= 1` |
| `STALL`    | Insufficient evidence or flawed argument | Stays at current status                   | Returns to finding-validator for remediation; a STALL may include specific objections to address |
| `KILLED`   | Finding is false positive or irrelevant  | Current → `KILLED` (terminal)             | No recovery — a killed finding stays killed; document the reason in `rebuttal_result` |

## FindingStatus lifecycle

```
DETECTED → CONFIRMED → EXPLOITED → CHAINED → VALIDATED → REPORTED
              ↓            ↓           ↓          ↓
            KILLED       KILLED      KILLED     (final)
```

- **DETECTED**: Initial state. A potential vulnerability has been
  identified but not yet verified.
- **CONFIRMED**: The vulnerability exists (e.g., error-based detection,
  version match with demonstrated impact).
- **EXPLOITED**: A working proof-of-concept demonstrates impact.
- **CHAINED**: The finding participates in a chain with other findings
  (see `engine/chain_engine.py`).
- **VALIDATED**: Passed the rebuttal gate (finding-checker ACCEPTED it)
  AND the evidence gate in `FindingsStore.update_status()`.
- **REPORTED**: Included in the final engagement report.
- **KILLED**: Terminal. Finding was a false positive, duplicate, or out
  of scope. Rebuttal verdict KILLED, or operator decision.

## Where verdicts are produced

1. **Seven-question pre-submit gate** (`references/seven-question-gate.md`):
   7 questions the operator answers before submitting a finding. Acts as
   a self-review before the finding enters the adversarial pipeline. Does
   NOT produce a verdict directly — it gates whether the finding is
   submitted at all.

2. **Finding-checker adversarial review** (`agents/finding-checker.md`):
   10 questions for blind adversarial review. Produces the canonical
   verdict: ACCEPTED / STALL / KILLED.

These two are complementary, not duplicates. The seven-question gate is
a pre-flight checklist; the finding-checker is an independent adversary.

## Engine enforcement

`FindingsStore.update_status()` in `engine/findings.py` enforces:
- Only valid transitions per `STATUS_TRANSITIONS` map
- Evidence gate for VALIDATED transition (evidence present, tag not
  unproven, steps to reproduce exist)
- KILLED is terminal (no outgoing transitions)
- REPORTED is terminal (no outgoing transitions)
