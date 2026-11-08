---
name: quarry:validate
description: Finding validation pipeline — evidence hygiene, dedup, 4 gates, 7-Question Gate, adversarial rebuttal
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:validate [finding_id|--all]

Runs the full validation pipeline on a specific finding or on all
pending ones. Nothing gets reported (`/quarry:report`) without passing
through this pipeline — it is the plugin's anti-fabrication control
implemented as process, not just a rule in `CLAUDE.md`.

## Argument

- `<finding_id>` (e.g. `F-A1B2C3D4`) — validate only that finding (or
  chain, if the ID starts with `C-`).
- `--all` — validate all findings with status `DETECTED`, `CONFIRMED`
  or `EXPLOITED`, and all chains with status `candidate`. With no
  argument, ask which mode is desired — do not default to `--all`,
  because running rebuttal against everything can be expensive in
  tool calls (see `budget.py`).

## The 5 stages, in strict order

Do not skip stages even if the finding "looks obviously valid" — the
order exists because each stage depends on the previous one having
cleaned the ground.

### 1. Evidence hygiene (`skills/validate/evidence-hygiene`)

Verify for each finding/chain:
- Is the evidence reproducible (complete request/response, or tool
  output with timestamp)? If missing, **do not advance** — go back to
  `/quarry:hunt` for that cell and capture real evidence first.
- Does the evidence demonstrate the claimed impact, or just a
  precondition? (e.g. "the parameter is reflected" is not the same as
  "the XSS executes").
- Are targets anonymized where appropriate for future reuse, without
  losing the real evidence in the current engagement?

Findings that fail hygiene stay at `DETECTED` with a note about what
evidence is missing. They do not advance to the next stage.

### 2. Deduplication (`skills/validate/dedup`)

For the set that passed hygiene:
- Group findings that share the same root cause even if symptoms differ
  (e.g. same endpoint without output encoding, reflected in 3 different
  parameters).
- Merge duplicates into a single finding with multiple
  `steps_to_reproduce`, keeping the oldest ID and marking the others
  as `KILLED` with `reason="duplicate of F-XXXXXXXX"`.
- For chains: verify they are not the same chain seen from two different
  pairs of findings.

### 3. The 4 gates (`skills/validate/finding-validation`)

Each finding must pass all 4, explicitly, documenting the answer:

1. **Refutation** — is there a valid reason to kill this finding?
   Walk through the `REFUTATION_QUESTIONS` from `engine/rebuttal.py` (is
   it reproducible by someone with no prior context?, does a WAF/rate-
   limiter/CSRF token already block it?, does the PoC demonstrate the
   impact or just a precondition?, is it an informational observation
   rather than a vulnerability?, could it be a scanner false positive?,
   is the severity inflated relative to what was demonstrated?, would a
   real attacker exploit this or is it theoretical?, is the endpoint
   reachable from an external/unprivileged position?, are there
   deployment assumptions that don't hold in production?, has dedup been
   checked already?).
2. **Reachability** — is the vulnerable endpoint/function reachable
   within the authorized scope, without requiring access the modeled
   attacker wouldn't have?
3. **Trigger** — is there a concrete, repeatable trigger (request,
   command, sequence of actions) that activates the vulnerability, not
   just a theoretical condition?
4. **Impact** — is the claimed impact Demonstrated or is it inferred/
   assumed? If it is `Inferred` or `Unproven`, the reported severity
   cannot exceed what that evidence actually supports.

A finding that fails any of the 4 gates does not advance — it is sent
back to `DETECTED`/`CONFIRMED` with the specific reason, or killed if
the gate shows it is invalid.

### 4. 7-Question Gate (triage, `skills/validate/triage-gate`)

Final triage checklist before adversarial rebuttal — 7 questions any
external reviewer would ask first. If `skills/validate/triage-gate/
SKILL.md` is not written yet, use the standard 7 bug-bounty triage
questions as a baseline (known duplicate, within program/client scope,
severity consistent with real impact, complete and reproducible PoC,
does not require unauthorized social engineering, is not a "best
practice" with no demonstrable impact, affects a version/configuration
actually deployed) and flag it as a content gap.

### 5. Adversarial rebuttal (`engine/rebuttal.py`)

For each finding that made it here:
1. `RebuttalEngine.start_session(finding_id, max_rounds=3)`.
2. Generate the checker prompt with `get_checker_prompt(...)` — **the
   checker acts blind**: it must not receive the operator's reasoning
   or the engagement context, only the finding and its evidence in
   JSON. If you are playing both roles in the same session, genuinely
   simulate the adversarial stance — do not validate your own work
   with a courtesy objection.
3. The generator (validator role, with full context) responds to the
   checker's challenge.
4. Record the round with `record_round(finding_id, challenge, response,
   outcome)`, where `outcome` is `ACCEPTED`, `STALL` or `KILLED`.
5. Repeat until `ACCEPTED`/`KILLED`, or up to 3 rounds (`EXHAUSTED`).
6. Map the final result to the finding:
   - `ACCEPTED` → `FindingsStore.update_status(id, FindingStatus.VALIDATED)`,
     `rebuttal_result="ACCEPTED"`.
   - `KILLED` → `update_status(id, FindingStatus.KILLED, reason=...)`.
   - `STALL`/`EXHAUSTED` → the finding does not advance; report it to
     the operator as "needs more evidence", never inflate it to
     `VALIDATED` out of loop fatigue.

## Edge cases

- **Finding already `VALIDATED` or `REPORTED`**: do not reprocess unless
  the operator explicitly requests re-validation (e.g. new evidence
  surfaced that contradicts it).
- **Chain (`C-XXXXXXXX`) instead of finding**: the pipeline applies the
  same way, but the "finding" being evaluated is the combination — the
  checker must specifically attempt to refute that the combination
  produces more impact than each part separately, not just refute each
  part.
- **`--all` with high volume**: before starting, show how many findings/
  chains will enter the pipeline and the estimated cost in tool calls;
  if it exceeds the available budget for the `validating` phase
  (`BudgetManager.get_tracker("validating")`), confirm with the
  operator before proceeding or suggest prioritizing by severity.
- **Repeated STALL in the same finding category**: if several findings
  of the same class end up in STALL for the same reason (e.g. "lacks
  real impact evidence" on multiple XSS), flag it as a pattern —
  the hunt skill's methodology likely needs adjustment, not just each
  individual finding.

## Expected output

Final table per finding/chain: ID, title, stage where it terminated
(hygiene/dedup/gates/triage/rebuttal), result (`ACCEPTED`/`STALL`/
`KILLED`), and reason in one line. Aggregate summary
(`FindingsStore.summary()` + `RebuttalEngine.summary()`).

Recommended next step: `/quarry:report` if there are `VALIDATED`
findings; if everything ended in `STALL`, go back to
`/quarry:hunt`/`/quarry:chain` for additional evidence before retrying
validation.
