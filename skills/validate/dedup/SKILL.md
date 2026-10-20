---
name: dedup
description: >
  Stage 2 of the validation pipeline (`/pt:validate`). Collapse findings that share the same
  underlying root cause — including ones discovered on different endpoints, by different
  hunt-* skills, or in different sessions — into a single finding with multiple instances,
  before the 4 gates and triage-gate spend effort reviewing the same bug twice. Use after
  evidence-hygiene has confirmed the candidate set has real evidence, and before
  finding-validation. Do NOT use this to merge two genuinely distinct vulnerabilities that
  happen to look similar on the surface — same CWE alone is not enough; the root cause and
  remediation must match too.
metadata:
  type: validate
  phase: validating
  tools: [findings.py, diff, grep]
depends_on: [evidence-hygiene]
feeds_into: [finding-validation]
---

## Signals

- Two or more findings in the current batch share a `vuln_class`/CWE and were found on
  related endpoints or via similar techniques.
- A hunt-* skill's methodology was applied across multiple endpoints and surfaced the same
  flaw repeatedly (e.g. missing output encoding reflected in three different parameters of
  the same handler).
- `/pt:chain`'s matrix mode flagged a pair as a suspected spurious chain between two symptoms
  of the same bug (per `chain-analysis`'s gotchas).
- Re-running validation after a prior engagement's findings were imported and may overlap with
  newly discovered ones.

## Prerequisites

- Candidate findings have passed `evidence-hygiene` (each has real, timestamped evidence —
  deduplication decisions on unverified evidence are unreliable).
- Access to each candidate's full finding record, not just its title/severity.

## Methodology

1. **Group by surface signal first, to build a short candidate-duplicate list cheaply.** Bucket
   findings by `vuln_class`/CWE and by asset family (same app, same service) before doing any
   deep comparison — this is a cheap pre-filter, not the actual dedup decision.
   ```bash
   jq -r '.[] | [.vuln_class, .asset, .id] | @tsv' findings.json | sort
   ```

2. **For each candidate pair/group, check the three dedup conditions explicitly.** All three
   must hold for it to be a true duplicate, not just two:
   - **Same CWE** (surface classification matches).
   - **Same root cause** — the actual mechanism is identical (e.g. "no output encoding on
     user-controlled fields rendered into HTML", not just "both are XSS" — a reflected XSS in
     a search param and a stored XSS in a profile bio share a CWE but not a root cause unless
     the encoding gap is the literal same code path/library).
   - **Same remediation** — the fix a developer would ship is the same change (same function,
     same library call, same validation layer), not two unrelated fixes that happen to address
     the same CWE.

3. **Verify root cause with evidence, not assumption.** Where source is available, confirm both
   instances trace to the same function/module. Black-box, confirm the behavioral signature
   matches exactly (same error message, same bypass technique, same missing header) rather than
   inferring sameness from the vuln class label alone.

4. **Keep the instance with the strongest evidence as the primary record.** "Strongest" means:
   most complete evidence (full request/response over partial), most convincing impact
   (demonstrated over inferred), and if tied, the earliest-discovered ID (per project
   convention, oldest ID wins on a tie — keeps history stable across re-runs).

5. **Fold the other instances in as additional reproduction instances, don't discard them.**
   Attach each duplicate's endpoint/parameter and its own evidence reference to the primary
   finding's `steps_to_reproduce`/instance list — this strengthens the "it's not a one-off"
   case (per `finding-evidence-standards.md`'s IDOR "ideal" bar) rather than losing the
   information.
   ```bash
   # mark the non-primary instance explicitly, keep the finding, not silently delete it
   FindingsStore.update_status(dup_id, FindingStatus.KILLED, reason=f"duplicate of {primary_id}")
   ```

6. **Apply the same test to chain candidates, not just standalone findings.** Two chain
   candidates that reach the same end-state via the same pair of underlying findings — just
   discovered from the matrix side vs. the graph side of `chain_engine.py` — are the same chain,
   not two. Cross-check `chain_id` candidates by their `findings` set before treating both as
   independently reportable.

7. **When in doubt, don't merge.** A false merge hides a second, genuinely distinct bug behind
   one write-up — worse for the client than a false non-merge, which only costs a slightly
   longer findings list. If the root-cause match is uncertain, keep both and note the suspicion
   in each record for a human to resolve, rather than deciding unilaterally.

## Validation gate

- [ ] Every merge decision states explicitly which of the three conditions (CWE, root cause,
      remediation) was checked and how, not just "looks similar."
- [ ] The primary (surviving) finding carries every duplicate instance's endpoint/evidence as
      an additional reproduction, not just a count.
- [ ] Every non-primary duplicate is marked `KILLED` with `reason="duplicate of <primary_id>"`
      and preserved in the record, never silently deleted.
- [ ] Chain candidates are checked for duplication by their component-findings set, not just
      by name/description similarity.

## Gotchas

- Same CWE is the weakest of the three signals and the one most likely to produce a false
  merge — an IDOR on `/invoices/{id}` and an IDOR on `/users/{id}` are the same CWE but may have
  entirely different root causes (one a missing ownership check, the other a predictable-ID
  issue with no check at all) with different fixes; don't merge on CWE alone.
- The reverse failure — reporting the same root cause as N separate findings "to be thorough"
  — inflates the apparent severity count without adding real information, and `finding-
  evidence-standards.md`'s transversal rules flag this explicitly as a quality defect (Regla 7,
  anti-fabrication rules).
- A finding discovered independently in two different engagement phases (e.g. once during
  `js-analysis`, once during `hunt-api-abuse`) is a legitimate dedup candidate even though the
  discovery paths look unrelated — check root cause, not discovery method.
- Don't dedup across different environments (staging vs. prod) even if the root cause is
  identical — document the delta per `finding-evidence-standards.md`'s N/A scenarios instead of
  collapsing them.
