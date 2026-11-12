---
name: triage-brocards
description: >
  Fast accept/dismiss/needs-more-info triage of candidate findings using seven
  brocards (decision rules) BEFORE deep validation. Use when the pipeline generates
  more candidates than the budget can fully validate: scanner leads, analyzer hits,
  agent hypotheses, externally submitted reports. Keywords: triage, brocards, false
  positive filter, accept dismiss, report intake, lead scoring, seven rules.
  Do NOT use as a replacement for full validation of accepted candidates — brocards
  sort the queue, the validation gate decides what ships.
metadata:
  type: validate
  phase: validation
  mitre_attack: []
  tools: []
depends_on: [finding-discipline]
feeds_into: [finding-validation, evidence-hygiene, dedup]
chains_with: []
---

## Purpose

Validation budget is finite; candidate volume is not. Brocards (legal Latin:
decision rules of thumb) let the validator sort each candidate in under two
minutes into ACCEPT (send to full validation), DISMISS (record why, move on),
or INFO-NEEDED (specific missing fact blocking the decision). Every decision
is logged with the brocard number — "dismissed per B3" is auditable; a silent
drop is not.

## The Seven Brocards

**B1 — No trigger, no finding.** A candidate without a demonstrated or
concretely reproducible trigger (request, input, sequence) is at most a
hypothesis. → INFO-NEEDED: "what exact input causes the effect?" If none can
be produced: DISMISS.

**B2 — Version ≠ vulnerability.** A fingerprint (banner, version string,
framework detection) plus a public CVE is not evidence the CVE is exploitable
here — patches get backported, builds differ. → INFO-NEEDED: live trigger or
reachability proof. Dismiss if the version turns out patched (check vendor
advisory affected-ranges, not just the number).

**B3 — The scanner is a witness, not a judge.** Tool output alone (nuclei,
burp active scan, analyzer SARIF) never survives triage. One manual
reproduction outside the scanner is the entry fee to full validation.
→ DISMISS if it cannot be reproduced manually once.

**B4 — Impact must name its victim and asset.** "Could lead to compromise"
without a specific data/identity/system affected fails. Map the claimed
impact to a concrete asset from asset-map; if the asset is out of scope or
imaginary → DISMISS; if the asset exists but the path to it is unproven →
INFO-NEEDED on the missing link.

**B5 — By-design is not a bug (until it chains).** Behavior matching
documented functionality (public profile pages, intentional redirects,
self-XSS requiring the victim to paste payloads into their own console)
→ DISMISS as a standalone finding, BUT record it as chain material in the
brain — dismissed-by-design items frequently become chain links.

**B6 — One observation, one claim.** A candidate bundling three effects
("SQLi AND RCE AND data theft") is split into separate candidates before
triage; each stands or falls on its own evidence. Bundles hide weak links
behind strong ones.

**B7 — Duplicate or derivative?** Check dedup against existing findings and
the never-submit list BEFORE spending validation budget. A candidate that is
a weaker restatement of an accepted finding merges into it (recorded), not
validated separately.

## Decision protocol

1. Apply B1–B7 in order; stop at the first decisive brocard.
2. Record: candidate id, brocard applied, decision, one-line reason, missing
   info (for INFO-NEEDED).
3. INFO-NEEDED items get ONE follow-up cycle; unanswered → DISMISS with the
   question recorded in the engagement's coverage gaps.
4. Accepted candidates enter finding-validation at DETECTED status with the
   brocard trail attached.
5. Dismissals feed the report's "leads considered and rejected" appendix —
   clients see the filter working, and future engagements don't re-triage
   the same noise (record anonymized in engine/knowledge.py).

## Gotchas

- Brocards sort; they do NOT prove. An ACCEPT only means "worth full
  validation" — findings still ship at the evidence standards bar.
- Never dismiss for difficulty ("hard to exploit") — only for evidence or
  scope reasons. Hard-but-real goes to ACCEPT with a budget note.
- B5 dismissals must be revisited at chaining time: chain-analyst reads the
  dismissed-by-design list as candidate chain links.
- Externally submitted reports (bug bounty intake) get the same seven rules —
  no deference to the reporter's claimed severity.
