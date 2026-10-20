---
name: triage-gate
description: >
  Stage 4 of the validation pipeline (`/pt:validate`) — the 7-Question Gate. A final,
  bug-bounty-style triage checklist run after the 4 structural gates and before the blind
  adversarial rebuttal loop, asking the questions any external reviewer or client triager would
  ask first. Use on every finding/chain after finding-validation has passed it, as the last
  operator-context checkpoint before rebuttal. Do NOT use this in place of finding-validation's
  four gates — triage-gate assumes those already passed and focuses on program/report-level
  fitness (novelty, scope, evidence sufficiency for a reader), not on whether the bug is
  technically real.
metadata:
  type: validate
  phase: validating
  tools: [rebuttal.py, findings.py]
depends_on: [finding-validation]
feeds_into: []
---

## Signals

- A finding/chain just passed all four gates in `finding-validation` and is queued for the
  adversarial rebuttal loop.
- Preparing a batch for `--all` validation and wanting a fast, structural pre-check before
  spending rebuttal-loop budget per `/pt:validate`'s cost warning.
- A finding resembles something already reported earlier in the same engagement, or matches a
  pattern commonly rejected by clients as "best practice, not a vulnerability."

## Prerequisites

- Finding/chain has an explicit PASS on all four `finding-validation` gates.
- Full visibility into the engagement's scope (`scope.txt`), prior findings in this engagement,
  and the client's RoE for what counts as in-scope/excluded.

## The 7 questions

Answer each explicitly, in order. "Yes" is the passing answer to every question as phrased
below; any "no" blocks the output from `ACCEPTED`.

1. **Is it real?** Beyond the four gates already passed — does this hold up as an actual
   security issue and not a style/aesthetic nit, a non-issue flagged by an overly aggressive
   scanner rule, or a misunderstanding of intended behavior?

2. **Is it reachable?** Confirmed again at the triage level, specifically: would the client's
   own triager, reading only the write-up, agree the attacker position required is realistic
   and not an edge case requiring implausible setup?

3. **Is it triggerable?** Does the write-up, as currently drafted (not just the raw evidence
   behind it), make the trigger concrete and literal enough that someone outside this
   engagement could run it themselves? A gate-3 PASS on raw evidence doesn't guarantee the
   *write-up* carries that evidence forward clearly.

4. **Is it impactful?** Does the demonstrated impact (per gate 4) justify the severity being
   proposed for the report, specifically in this client's context — not impact in the abstract,
   but impact given what this system actually holds/does (e.g. an info leak is worth more on a
   PII-heavy system than on a marketing site with no sensitive data).

5. **Is it novel?** Has this exact finding (same root cause) already been reported earlier in
   this engagement, in a previous retest, or is it a known/accepted-risk item the client has
   already documented as "won't fix" with a stated rationale? Cross-check against `dedup`'s
   output and any prior-engagement memory per project CLAUDE.md "memory-first."

6. **Is it in scope?** Confirmed again at the triage level against `scope.txt` and the RoE's
   excluded-techniques list — not just "the asset is in scope" but "this specific technique/
   impact category wasn't explicitly excluded" (e.g. a finding that required a volumetric
   technique the RoE bans).

7. **Is the evidence sufficient for a reader who wasn't here?** Distinct from `evidence-
   hygiene`'s raw-artifact check — this asks whether the *write-up as it will appear in the
   report* carries enough of that evidence forward (right excerpts, right context, nothing
   requiring "trust me, I saw it work") for the client's own technical reviewer to independently
   agree it's valid.

## Methodology

1. Pull the finding/chain's current write-up (not just the raw record) — this gate evaluates
   report-readiness, so review what would actually ship.
2. Answer all 7 questions explicitly, each as a short justified yes/no, not a single paragraph
   covering all of them vaguely.
3. Determine the outcome:
   - **ACCEPTED** — all 7 are "yes." Proceed to the adversarial rebuttal loop
     (`engine/rebuttal.py`).
   - **NEEDS_WORK** — one or more are "no," but the gap is fixable (write-up needs tightening,
     missing novelty cross-check, scope boundary needs re-confirming). State exactly which
     question(s) failed and what's needed, then re-run only this gate once fixed — don't restart
     the whole pipeline from evidence-hygiene unless the fix required new evidence.
   - **REJECTED** — one or more are "no" for a reason that can't be fixed by better writing or
     more evidence (genuinely out of scope, genuinely a duplicate of an accepted-risk item,
     genuinely not impactful in this client's context). Kill the finding with the specific
     question and reason.
4. Record the outcome and the per-question answers on the finding record — `report-writing`
   and any future retest will need this trail.
5. On `ACCEPTED`, hand off to the rebuttal loop per `/pt:validate` stage 5 — note that triage-
   gate's "yes" answers are operator-context judgments and carry no weight with the blind
   checker, which re-derives everything from the evidence alone.

## Validation gate

- [ ] All 7 questions answered explicitly and individually, not summarized.
- [ ] Outcome is exactly one of `ACCEPTED` / `NEEDS_WORK` / `REJECTED` — no soft middle ground.
- [ ] `NEEDS_WORK` findings specify exactly which question(s) failed and what's needed to
      re-pass, not a vague "needs polish."
- [ ] `REJECTED` findings carry the specific disqualifying question and reason, preserved for
      the report's appendix of findings not included.

## Gotchas

- A finding can be technically airtight (four gates PASS) and still get `REJECTED` here — e.g.
  a real, demonstrated issue the client has already accepted as risk in writing. Triage-gate is
  where program/client context, not technical correctness, is the deciding factor.
- Don't let "is it novel" quietly become "is it impressive" — a known, unglamorous issue (a
  missing security header, a verbose error) is still novel if it genuinely hasn't been reported
  in this engagement yet; novelty is about duplication, not about how interesting the bug is.
- `NEEDS_WORK` on question 7 (evidence sufficiency for a reader) is extremely common and not a
  sign the finding is weak — it usually just means the write-up needs the right excerpt pulled
  forward from the raw evidence, which is cheap to fix without re-testing anything.
- Running this before the rebuttal loop, not after, is intentional — it catches report-level and
  scope/novelty problems the blind checker has no visibility into (it never sees other findings
  in the engagement or the RoE), so don't skip straight to rebuttal assuming it covers the same
  ground.
