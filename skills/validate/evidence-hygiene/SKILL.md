---
name: evidence-hygiene
description: >
  Stage 1 of the validation pipeline (`/pt:validate`). Verify that each finding's raw
  evidence actually meets the minimum bar before anything else runs: timestamped,
  reproducible, complete request/response (or tool output), and tagged with the correct
  Demonstrated/Inferred/Unproven label for what it actually shows. Use immediately after
  a finding comes out of hunting/chaining and before dedup/finding-validation/triage-gate
  touch it — those stages assume the evidence is already sound. Do NOT use this to judge
  whether the finding itself is real or severe enough — that's finding-validation's and
  triage-gate's job; this skill only checks evidence quality and labeling.
metadata:
  type: validate
  phase: validating
  tools: [curl, burpsuite, diff, finding-evidence-standards.md]
depends_on: [finding-discipline]
feeds_into: [dedup]
---

## Signals

- A finding/chain just arrived from a */chain-* skill with status `DETECTED` or
  `CONFIRMED` and is about to enter `/pt:validate`.
- Reviewing a batch of findings before `--all` validation to catch evidence gaps cheaply,
  before spending rebuttal-loop budget on something that was never going to survive.
- A finding's `evidence_tag` looks inconsistent with what's actually attached (e.g. tagged
  Demonstrated but the only artifact is a scanner's version-detection line).

## Prerequisites

- The finding/chain record (`finding-template.md` shape) with whatever evidence artifacts
  were captured at discovery time.
- `references/finding-evidence-standards.md` — the per-vuln-class minimum evidence table this
  skill checks against.

## Methodology

1. **Check presence first, content second.** Confirm something is actually attached: a full
   request+response pair, a tool output file, or a screenshot/recording — not a paraphrase in
   the description field. A finding whose "Evidence" section is prose with no artifact fails
   here regardless of how convincing the prose is.
   ```bash
   test -s evidence/idor-001-request.txt && test -s evidence/idor-001-response.txt && echo OK
   ```

2. **Check completeness.** The request must include the headers that matter for interpreting
   it (`Authorization`, `Cookie`, `Content-Type`), not just the path. The response must show
   the actual effect, not just a status code — a bare `200 OK` with no body is not evidence of
   impact for most vuln classes.

3. **Check timestamp.** Every artifact needs a verifiable "when" — a tool's own timestamp
   output, a `curl -i` response `Date` header, or an explicit note of when the test ran. No
   timestamp means it can't be confirmed recent or correlated with a target-side log if the
   client asks later.

4. **Check against the class-specific minimum from `finding-evidence-standards.md`.** Look up
   the finding's `vuln_class` in that reference and confirm the attached evidence meets at
   least the "Mínimo" bar for that class (e.g. SSRF needs either visible response content or an
   OOB callback with a correlated timestamp — a bare connection timeout does not qualify). If
   the evidence only meets an "N/A común" pattern listed there (generic 500, reflected-but-not-
   executed payload), the finding does not pass hygiene as currently evidenced.

5. **Check reproducibility independent of transient state.** If the PoC depends on a specific
   session/token that may have expired, or on data seeded only in a test environment, flag
   this explicitly rather than letting the finding imply universal reproducibility:
   ```bash
   curl -i -s https://target/api/export/1 > evidence/idor-001-retest.txt
   diff evidence/idor-001-request.txt evidence/idor-001-retest.txt
   ```

6. **Check the evidence tag matches the evidence, not the hope.** Re-derive the tag
   independently from what's attached (per `finding-discipline`'s three tiers) and compare it
   to the tag currently on the record. A mismatch (usually over-tagged) is a hygiene defect,
   not a gate-3/triage defect — fix the label here before it propagates further.

7. **Check anonymization readiness for reuse.** If this technique/finding is a candidate for
   memory reuse (project CLAUDE.md "memory-first"), confirm target identifiers can be swapped
   for `{target_ip}`/`{target_domain}` placeholders without losing the technical structure.

8. **Route the outcome.**
   - Evidence complete, timestamped, meets the class minimum, tag matches → passes to `dedup`.
   - Evidence missing or insufficient → finding stays at its current status with an explicit
     note of exactly what's missing (not a vague "needs more evidence") and is sent back to the
     originating hunt/chain skill to capture it for real, not inferred after the fact.
   - Tag mismatch only (evidence itself is fine) → correct the tag in place and proceed.

## Validation gate

- [ ] Every finding entering `dedup` has a complete, timestamped evidence artifact attached
      (not paraphrased).
- [ ] Evidence meets or exceeds the class-specific minimum in `finding-evidence-standards.md`.
- [ ] Evidence tag (Demonstrated/Inferred/Unproven) matches what the artifact actually shows,
      independently re-derived, not copied from the original write-up.
- [ ] Any transient-state dependency (session, seeded test data) is stated explicitly, not
      implied as universally reproducible.

## Gotchas

- A scanner's raw output (nikto/nuclei/sqlmap) is a lead, not evidence — per
  `finding-evidence-standards.md`'s transversal rule, every finding needs at least one manual
  reproduction outside the scanner before it counts as hygiene-clean.
- Don't confuse "the request looks complete" with "the response proves impact" — the two most
  common hygiene failures are a request with no corresponding response capture, and a response
  that's generic/ambiguous dressed up as proof.
- Fixing a mismatched tag here is a correction, not a downgrade decision — if the evidence
  genuinely only supports Inferred, say so plainly; don't soften the finding to avoid looking
  like a failure at this stage.
- This stage runs before dedup on purpose — bad evidence on a near-duplicate wastes effort
  deciding which duplicate has "the strongest evidence" when neither has any yet.
