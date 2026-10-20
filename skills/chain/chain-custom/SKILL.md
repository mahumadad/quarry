---
name: chain-custom
description: >
  Framework for analyzing ad-hoc exploit chains that don't match any
  predefined pattern (chain-web-to-rce, chain-auth-to-takeover,
  chain-info-to-exploit, chain-ssrf-to-cloud, chain-xss-to-account-takeover,
  chain-idor-to-mass-data). Use when chain-analysis produces a candidate
  whose shape is novel for this engagement, or when fewer than two
  findings exist but a single finding's capability-map entry suggests an
  unusual escalation worth structured analysis anyway.
  Do NOT use this as a shortcut to skip the more specific chain-* skill
  when the candidate actually matches one — check fit against all six
  pattern skills first; this is the fallback, not the default.
metadata:
  type: chain
  phase: chaining
  tools: [chain_engine.py, burp, custom_scripts]
depends_on: [chain-analysis]
feeds_into: [finding-validation, report-writing]
chains_with: []
---

## Signals

- chain-analysis scored a pair/path ≥1 but it doesn't fit the shape of any of the six
  pattern-specific chain skills (e.g. a logic flaw + a business-rule bypass with no
  injection/auth component at all, or a cross-protocol chain like SMTP+web).
- A novel multi-hop path through the pivot graph spans three or more findings where no
  single pairwise pattern captures the whole thing.
- The engagement is testing an unusual system type (hardware/IoT, blockchain/smart contract,
  ML pipeline) where the standard web-vuln chain patterns don't map cleanly.

## Prerequisites

- chain-analysis has run and produced the candidate — this skill develops a candidate into a
  PoC, it does not generate candidates from scratch.
- Confirm the fit check: re-read the description/signals of all six pattern skills and note
  explicitly why none applies, so the choice to go custom is itself recorded reasoning, not a
  default.

## Methodology

1. **State the chain hypothesis precisely.** Write the chain as a sequence of
   (finding/capability) → (precondition satisfied) → (next finding/capability) steps, exactly
   as chain-analysis's graph mode represents it. If it can't be stated this precisely, it's
   not ready for PoC development — go back to chain-analysis or capability-map for more
   evidence first.

2. **Identify the weakest link.** Of all the steps in the hypothesized chain, find the one
   with the least evidence/most assumption. That step is where to spend verification effort
   first — a chain is only as strong as its weakest confirmed link, and there's no point
   building out a PoC for steps 2-4 if step 1's precondition doesn't actually hold.

3. **Verify each link independently before combining.** Test each precondition-satisfies-
   next-step transition on its own, with its own evidence, before attempting the full
   end-to-end chain. This mirrors the other chain skills' approach and keeps the analysis
   falsifiable at each hop rather than only as an all-or-nothing final demo.

4. **Build the minimal end-to-end PoC.** Once every link is independently verified, construct
   the smallest demonstration that proves the full chain fires start to finish, following the
   same minimal-impact principles as the pattern-specific skills (no destructive/persistent
   actions without explicit operator sign-off).

5. **Decide on retroactive pattern classification.** After the chain is validated, check
   again whether it actually resembles one of the six patterns after all (sometimes this is
   only clear in hindsight) — if so, note the equivalent pattern in the write-up for
   consistency with other findings of that shape; if genuinely novel, document it fully as
   its own pattern so a future engagement (or chain-analysis's heuristics) can recognize it
   next time.

## Validation gate

- Same four gates as every other chain skill (via finding-validation): Refutation,
  Reachability, Trigger, Impact — a custom chain gets no lighter bar for being novel.
- The "why this doesn't fit a predefined pattern" reasoning from Prerequisites step is
  preserved in the write-up, not discarded once the PoC works.
- Every link's independent verification evidence is preserved, not just the final end-to-end
  demo — reviewers need to see each hop, not just the conclusion.

## Gotchas

- Novel chains are exactly where overclaiming creeps in, because there's no established
  pattern skill's gotchas list to check against — be more conservative here, not less, about
  labeling something Demonstrated vs Inferred.
- A chain that only becomes interesting when you combine three or more low-severity findings
  needs a correspondingly higher bar of end-to-end proof — reviewers (and clients) are
  rightly skeptical of "many smalls make a big" claims without a crisp, reproducible full
  demo.
- If budget runs out before the full chain is verified, report what was verified as
  individual findings plus an explicit "potential chain, not fully verified, here's what's
  missing" note — per cobertura rules, a documented gap beats a rushed, under-evidenced
  claim.
- Resist the temptation to force-fit a weird finding into one of the six named patterns just
  to use a more "official-sounding" skill — a mislabeled pattern can mislead whoever reads
  the report into applying the wrong mitigations.
