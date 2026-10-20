---
name: finding-validation
description: >
  Stage 3 of the validation pipeline (`/pt:validate`). Run every finding/chain through four
  explicit gates — Refutation, Reachability, Trigger, Impact — each of which must PASS on its
  own merits or the finding is downgraded (severity/evidence tag) or killed outright. Use after
  evidence-hygiene and dedup have cleaned the candidate set, and before triage-gate. Do NOT use
  this as a substitute for the blind adversarial rebuttal loop (`engine/rebuttal.py`) — these
  four gates are the operator-facing structural check; the rebuttal loop that follows is a
  separate, context-free pass by a reviewer who never sees this reasoning.
metadata:
  type: validate
  phase: validating
  tools: [rebuttal.py, curl, burpsuite]
depends_on: [evidence-hygiene, dedup]
feeds_into: [triage-gate]
---

## Signals

- A finding/chain passed `evidence-hygiene` and `dedup` and is next in the `/pt:validate`
  pipeline, before triage-gate and the adversarial rebuttal loop.
- Re-validating a finding after new counter-evidence surfaced (a WAF rule that actually blocks
  the PoC, a precondition that turned out not to hold in prod).
- A chain candidate from `/pt:chain` needs its *combined* impact validated independently of
  whether its component findings already passed these gates individually.

## Prerequisites

- Finding/chain record with hygiene-checked evidence and no unresolved duplicate status.
- `engine/rebuttal.py`'s `REFUTATION_QUESTIONS` list available as the concrete checklist behind
  Gate 1 — this skill operationalizes those ten questions into four pass/fail checkpoints
  rather than inventing a separate framework.

## The four gates

Run all four, in order, for every finding — including ones that "obviously" look solid. Each
gate gets an explicit PASS/FAIL with a one-line reason; there is no partial pass. A FAIL on any
gate stops the finding from advancing as currently stated — it is downgraded (severity, evidence
tag) or killed, never waved through with a caveat buried in the write-up.

### Gate 1 — Refutation

**Question:** Is there a valid reason to kill this finding?

Work through `engine/rebuttal.py`'s ten `REFUTATION_QUESTIONS` explicitly:
reproducibility by someone with no prior context, whether an existing control (WAF, rate
limiter, CSRF token) already blocks it, whether the PoC demonstrates impact or just a
precondition, whether it's a real vulnerability vs. an informational observation, whether it
could be a scanner false positive, whether severity is overstated relative to what was shown,
whether a reasonable attacker would actually exploit it, reachability from an
external/unprivileged position, whether deployment assumptions hold in production, and whether
dedup was actually checked (not just assumed clean).

- **PASS** — none of the ten questions surfaces a disqualifying issue.
- **FAIL** — any question surfaces a real problem → finding is killed (if the problem is fatal,
  e.g. a control already blocks it) or sent back for more evidence (if the problem is a gap,
  not a disproof).

### Gate 2 — Reachability

**Question:** Is the vulnerable code path/endpoint/function actually reachable within the
authorized scope, by the attacker position this finding claims (anonymous, authenticated-low-
priv, internal-network, etc.) — without requiring access the modeled attacker wouldn't have?

- Check the finding's claimed starting position against what was *actually* used to trigger
  it. A finding exploited only after obtaining an internal-network foothold cannot claim
  "externally reachable" severity unless that foothold is itself independently demonstrated and
  in scope.
- Check against `trust-map`/`scope-discipline` output where available — a path that crosses a
  boundary documented as blocked needs that boundary's actual (not claimed) state confirmed.
- **PASS** — the path is reachable from the stated attacker position, confirmed by evidence
  (not inferred from architecture diagrams).
- **FAIL** — reachability requires an unverified or out-of-scope precondition → downgrade the
  attacker-position claim to match what's actually verified, or kill if no verified path exists.

### Gate 3 — Trigger

**Question:** Is there a concrete, repeatable trigger — an exact request, command, or action
sequence — that activates the vulnerability, not just a theoretical condition?

- The trigger must be literal and reproducible per `finding-discipline`'s PoC standard: exact
  request/command, exact preconditions, exact observable effect.
- A condition that is merely plausible ("the parameter looks unsanitized") without an actual
  executed trigger fails this gate regardless of how the code looks.
- **PASS** — the trigger was actually executed and its effect captured as evidence.
- **FAIL** — no trigger was executed, only inferred → the finding cannot exceed `Inferred` tier
  (per `finding-discipline`) until a real trigger is run; it does not advance as `Demonstrated`.

### Gate 4 — Impact

**Question:** Is the claimed impact demonstrated, or inferred/assumed?

- Re-check the impact statement against the evidence line by line: does the evidence show the
  claimed effect (data exfiltrated, command executed, privilege gained) or only a precondition
  for it (e.g. a reflected payload with no confirmed execution)?
- The reported severity/CVSS must not exceed what Gate 4's answer supports — an `Inferred`
  impact caps the severity language and CVSS accordingly (see `finding-discipline`'s tier
  rules), even if the underlying mechanism (Gates 2-3) is solid.
- For chains: the combined end-state impact must be independently re-derived here, not
  inherited from the component findings' individual impact ratings.
- **PASS** — impact is demonstrated by evidence matching the claim exactly.
- **FAIL** — impact exceeds what's shown → downgrade severity/tag to match the actual evidence;
  this is a correction, not a kill, unless the gap is total (no impact evidence at all, in which
  case it reduces to an observation, not a finding).

## Methodology

1. Load the finding/chain record plus its hygiene-checked evidence.
2. Run Gate 1 (Refutation) first — it's the cheapest to fail fast on, and a Gate-1 kill makes
   the remaining three moot.
3. Run Gates 2, 3, 4 in order, recording PASS/FAIL and the specific reason for each.
4. If all four PASS: finding advances to `triage-gate` unchanged.
5. If any gate FAILs with a correctable gap (missing a specific piece of evidence, an
   overstated metric): apply the correction (downgrade severity/tag/attacker-position) and
   re-run only the affected gate — do not silently re-pass the others.
6. If any gate FAILs with a disqualifying issue (a control blocks it, no real path exists, no
   trigger was ever run and none is feasible): kill the finding with the specific gate and
   reason recorded.
7. For chains specifically: after the four gates pass for the combined claim, confirm the
   combined severity doesn't just inherit the max of the component findings — it must be
   re-justified against what the *combination* demonstrably adds (per `chain-report.md`'s
   Combined CVSS section).

## Validation gate (meta — for this skill's own output)

- [ ] All four gates have an explicit PASS/FAIL and a one-line reason, for every finding/chain
      processed — no gate silently skipped because the finding "looked fine."
- [ ] Any downgrade (severity, evidence tag, attacker-position) is recorded with which gate
      forced it, not applied invisibly.
- [ ] A chain's combined impact passed Gate 4 independently of its components' individual Gate
      4 results.
- [ ] Killed findings carry the specific gate and reason, available to `report-writing`'s
      appendix of killed-during-validation items.

## Gotchas

- These four gates are deliberately the operator's own pass, run with full engagement context —
  they are not a substitute for `engine/rebuttal.py`'s blind checker, which runs next in the
  pipeline with zero context by design. Passing these four gates does not mean the finding is
  done; `triage-gate` and the rebuttal loop still apply.
- A finding can PASS Gates 1-3 and still FAIL Gate 4 — a real, reachable, triggerable bug whose
  demonstrated impact is much smaller than its theoretical ceiling. Report what Gate 4 actually
  supports, not the ceiling.
- Resist re-running a gate you already failed with the same evidence hoping it reads differently
  the second time — a FAIL stands until new evidence is actually captured, not re-argued.
- A chain inherits nothing automatically from its components passing these gates individually —
  the combined claim is a new claim and gets its own four-gate pass.
