# The 7-Question Gate

> Concept credit: H-mmer/pentest-agents. Adapted here as a mandatory validation
> gate for this plugin's findings pipeline.

Every finding MUST pass all seven questions below before it is submitted to a
bounty platform or included in a final report. Each question must be answered
**YES**. A **NO** blocks the finding — it is downgraded to a lead, sent back
for more work, or killed outright — unless an explicit override condition
applies, and overrides should be rare enough that using one is itself worth
a second look.

This gate sits downstream of `finding-validator` (which builds the finding
record) and is the last check before `finding-checker` or the operator signs
off. It does not replace adversarial review — it is the minimum bar a finding
must clear before adversarial review is even worth running.

---

## 1. Is it reproducible?

**The question:** Can someone with no prior knowledge of the target reproduce
this finding using only the steps provided?

**Why it matters:** A finding that can't be reproduced from its own writeup
isn't evidence, it's a claim. Triagers close unreproducible reports fast, and
rightly so — the burden of proof is on the reporter, not the reader.

**How to check:**
- Re-run the PoC from a clean state (fresh session/cookie jar, no leftover
  state from the original exploitation run) using *only* the numbered steps
  in the finding record.
- If the PoC depends on a specific timing window, race condition, or
  transient state, re-run it enough times to report a real success rate, not
  "it worked once."
- If a tool was used, confirm the exact command and flags are captured
  verbatim in the finding, not paraphrased from memory.

**Common failures:**
- Steps reference UI state or values ("click the button next to the order I
  made earlier") that only exist because of actions taken off-screen.
- The PoC worked once during exploitation but fails on re-run because it
  depended on a session/token that has since expired or rotated.
- A race condition reported as deterministic when it actually requires
  several attempts, with the real success rate never stated.

**Override conditions (rare):**
- The vulnerability is real and demonstrated, but the specific trigger window
  has since closed (e.g. a one-time promo code, a bug that was live for a
  single deploy) — document this explicitly as a point-in-time finding with
  the original evidence (request/response, screenshots, timestamps) standing
  in for live reproduction, and say so plainly in the report.

---

## 2. Is the impact real?

**The question:** Does the PoC demonstrate actual impact — data exfiltrated,
command executed, account taken over — rather than just a precondition
(reflected input, open port, version number)?

**Why it matters:** This is the line between a vulnerability and an
observation. `finding-evidence-standards.md` defines per-class minimum
evidence for exactly this reason: a reflected parameter is not XSS until
script execution is confirmed, a DNS callback is not SSRF until an HTTP
callback or internal-resource read is confirmed.

**How to check:**
- Name the concrete impact in one sentence: what did the attacker actually
  get, read, change, or do? If the sentence has to use "could" or "might,"
  it has not cleared this question yet.
- Check the finding against `finding-evidence-standards.md` for its
  vulnerability class — does the evidence meet that class's stated minimum?
- Distinguish **Demonstrated** from **Inferred** from **Unproven** per
  `anti-fabrication-rules.md`. Only Demonstrated findings pass this question
  outright.

**Common failures:**
- "This endpoint is vulnerable to SQL injection" backed only by a generic
  500 error, with no DB error message, extracted data, or confirmed
  boolean/timing behavior.
- A version-detection hit (`Server: nginx/1.21.0`) presented as a finding
  with no exploit run against that specific version.
- An open port or exposed admin panel reported as a finding with no attempt
  to authenticate, exploit, or extract anything from it.

**Override conditions (rare):**
- Program policy explicitly asks for a specific class of precondition
  finding (e.g. some programs want exposed `.git` directories or debug
  endpoints reported even without a chained exploit) — cite the specific
  program policy line that asks for it.

---

## 3. Is it in scope?

**The question:** Is the affected asset explicitly listed in the
program/engagement scope? Have wildcard matches been verified, not assumed?

**Why it matters:** Out-of-scope findings are never submitted regardless of
severity — this is a hard rule in this plugin's `CLAUDE.md` (no action
without confirmed scope), and submitting out-of-scope work damages trust with
the program and can breach the engagement's rules of engagement.

**How to check:**
- Match the exact asset (domain, subdomain, IP, mobile app ID, API) against
  the scope document from `/quarry:engage` or `/quarry:scope`.
- For a wildcard scope entry (e.g. `*.example.com`), confirm the specific
  host actually resolves to infrastructure the program controls — a
  wildcard DNS match is not proof of ownership (CDN edge nodes, third-party
  SaaS on a subdomain, and abandoned DNS records are common traps).
- Check the out-of-scope list explicitly, not just the in-scope list —
  programs often carve out specific subdomains or asset classes from an
  otherwise-broad wildcard.
- If the vulnerable code/behavior lives in a third-party library or
  dependency, confirm the program's policy on third-party findings
  (most require reporting to the upstream vendor, not the program).

**Common failures:**
- Treating a wildcard scope entry as blanket permission without verifying
  the specific subdomain is actually operated by the target.
- Reporting a finding on infrastructure that resolves under the target's
  domain but is actually a third-party service (e.g. a status page, a
  marketing CDN) explicitly excluded by policy.
- Scope creep during a chain: step one is in scope, step two pivots to an
  asset that was never confirmed.

**Override conditions (rare):**
- None. This question has no override in this plugin's process — an
  out-of-scope finding is killed, full stop, even if severity is critical.
  If the asset should plausibly be in scope, that's a scope-clarification
  question to the operator/program, not a reason to submit.

---

## 4. Is it a duplicate?

**The question:** Has this exact vulnerability — same root cause, same
endpoint, same parameter — been reported before in this engagement?

**Why it matters:** Duplicate submissions waste triager time and, on bounty
platforms, are typically paid nothing or at a steep discount. Different
exploitation paths that trace back to the same root cause are still
duplicates — reporting them separately looks like padding the finding count.

**How to check:**
- Search `findings.json` (or the engagement's finding store) for the same
  endpoint + parameter + root cause before writing up a new finding.
- If the new finding shares a root cause with an existing one but reaches it
  through a different path (different parameter, different endpoint, same
  underlying missing check), treat it as a variant of the existing finding
  — add it as supporting evidence/additional affected endpoints on that
  finding, not a new one.
- When uncertain whether two findings share a root cause, trace both back to
  the actual code/config defect, not just the symptom. Two different
  payloads producing the same stack trace from the same unvalidated input
  point are one finding.

**Common failures:**
- The same broken access control check, missing on five different
  endpoints, reported as five findings instead of one finding with five
  affected endpoints.
- A finding reported against a parameter after a near-identical one was
  already logged with a different parameter name but the same missing
  validation function.
- Not checking `findings.json` at all before writing up, because the
  finding was discovered independently by a different phase/agent.

**Override conditions (rare):**
- Two vulnerabilities that look similar but have genuinely distinct root
  causes (e.g. same symptom — IDOR — but one is a missing ownership check
  and the other is a predictable-ID issue on an unrelated resource type) —
  document the distinct root causes explicitly so the triager doesn't have
  to re-derive that they're different.

---

## 5. Does it pass the never-submit list?

**The question:** Check the finding against `references/never-submit.md`. If
it matches any of the 15 hard rejects, it is blocked unless it meets one of
the matching upgrade conditions.

**Why it matters:** The never-submit list exists precisely because these
patterns look like findings but aren't — they're the most common source of
wasted operator and triager time, and submitting them erodes credibility for
every future report in the engagement.

**How to check:**
- Walk the finding against each of the 15 hard rejects in
  `never-submit.md` one by one — don't rely on gut-check pattern matching,
  since several of them (e.g. open redirect, SSRF DNS-only, GraphQL
  introspection) look superficially like real findings.
- If it matches a hard reject, check the corresponding row in the "Soft
  Rejects" upgrade table — has the specific upgrade condition actually been
  demonstrated (not just theorized)?
- If it doesn't match a hard reject outright but is adjacent to one (e.g.
  "missing rate limiting" that's really "weak rate limiting"), apply the
  same evidentiary bar the hard reject requires before treating it as
  exempt.

**Common failures:**
- Reporting CORS misconfiguration with `Access-Control-Allow-Origin: *` as
  a finding without checking whether `Access-Control-Allow-Credentials` is
  even present.
- Reporting an open redirect as a finding on its own, without the OAuth
  `redirect_uri` abuse or token-leak chain that would upgrade it.
- Reporting missing security headers as a standalone finding instead of as
  a contributing factor cited inside a finding that actually exploits the
  gap they left open.

**Override conditions (when NO can still advance):**
- Exactly the 8 upgrade conditions listed in the "Soft Rejects" table of
  `never-submit.md`, and only when the upgrade evidence is itself
  Demonstrated, not Inferred.
- A program-specific policy that explicitly asks for a listed item anyway
  (rare) — cite the policy line, same as question 2's override.
- An operator override with explicit, recorded justification, per the
  "Application" section of `never-submit.md`. This is a deliberate
  exception, not a default — it still gets logged with the finding's
  metadata.

---

## 6. Is the severity justified?

**The question:** Does the CVSS score match what was actually demonstrated,
not what's theoretically possible? Does each CVSS metric trace to specific
evidence?

**Why it matters:** Severity inflation is one of the fastest ways to lose
credibility with a triager, and it's explicitly one of the embarrassment-test
failure reasons in question 7. `CLAUDE.md` requires a CVSS 4.0 vector string
justified by what was verified — not by the worst-case scenario.

**How to check:**
- Walk every CVSS 4.0 metric and, for each one,
  point to the specific piece of evidence that justifies the chosen value.
  If a metric can't be justified from evidence, it defaults to the more
  conservative value, not the more severe one.
- Check whether impact was **Demonstrated** or only **Inferred**
  (`anti-fabrication-rules.md`). Inferred impact caps severity — it cannot
  be scored as if the worst-case inferred outcome were confirmed.
- Cross-check against `finding-evidence-standards.md`'s per-class "Mínimo"
  vs. "Ideal" evidence: a finding that only meets the "Mínimo" bar should
  not be scored as if it met "Ideal."
- Sanity-check the final score against the plain-English impact sentence
  from question 2 — if the sentence describes a moderate issue, a Critical
  score needs a very concrete justification for the gap.

**Common failures:**
- Scoring Confidentiality: High because the attacker "could theoretically"
  access all user data, when only one other user's record was actually
  accessed during testing.
- Scoring Attack Complexity: Low for a race condition that required dozens
  of attempts to trigger once.
- Using a public CVE's published CVSS score for a finding that only
  confirmed the vulnerable version is present, without re-deriving the
  score from what was actually demonstrated against this target.
- Scoring Scope: Changed without having demonstrated impact outside the
  vulnerable component's own security authority.

**Override conditions (rare):**
- A documented, program-accepted severity rubric that differs from strict
  CVSS 3.1 (some programs score by their own matrix) — use their rubric,
  but still justify every metric with evidence and say explicitly which
  rubric was used and why it differs from the default.

---

## 7. Would you mass-close this as a triager?

**The question (the "embarrassment test"):** If you were a program triager
seeing 50 reports a day, would you close this one immediately?

**Why it matters:** This is the holistic gut-check that catches everything
the first six questions might individually pass but that still adds up to a
weak report — the questions above are specific; this one is the integration
test. If the answer is "a tired triager would bounce this," fix it before
submission, not after a real rejection.

**How to check:**
- Read the finding record cold, as if seeing it for the first time with no
  context from having run the exploit.
- Check it against the common fast-close reasons explicitly: missing impact
  demonstration, unclear/incomplete steps, severity inflation, a pattern the
  triager will recognize as informational-only, or a control that already
  mitigates it (WAF rule, existing auth check elsewhere in the flow) that
  wasn't checked for.
- If possible, have a second agent or the operator do this read — someone
  who was not involved in finding or exploiting it is a better proxy for a
  triager than the person who already believes in the finding.

**Common failures:**
- The finding is technically accurate but the writeup assumes context the
  triager doesn't have (internal tool names, assumed familiarity with an
  earlier finding in the same chain).
- The finding is correct but describes a control that was already known and
  explicitly accepted as a risk by the program (check program
  docs/changelog before assuming it's unknown).
- The finding is real but so narrowly exploitable (single edge case, highly
  specific preconditions) that a triager would reasonably ask "so what,"
  and the report doesn't preemptively answer that.

**Override conditions (rare):**
- None, by design. This question is the final human-judgment check and
  doesn't have a formal override — if the honest answer is "yes, a triager
  would close this," the fix is to strengthen the finding (more evidence,
  clearer steps, honest severity), not to override the gate.

---

## Quick Checklist

- [ ] **Reproducible** — re-run from a clean state using only the written steps; success rate documented if non-deterministic.
- [ ] **Real impact** — concrete impact stated in one sentence with no "could"/"might"; meets the vulnerability class's evidence minimum.
- [ ] **In scope** — asset matched against the confirmed scope document; wildcard matches verified, not assumed; out-of-scope list checked too.
- [ ] **Not a duplicate** — checked against `findings.json`; same root cause under a different path treated as a variant, not a new finding.
- [ ] **Passes never-submit** — checked against all 15 hard rejects in `never-submit.md`; any match has a Demonstrated upgrade condition or an explicit, logged operator override.
- [ ] **Severity justified** — every CVSS 4.0 metric traces to specific evidence; Inferred impact capped, not scored as Demonstrated.
- [ ] **Passes the embarrassment test** — read cold as a triager would; no missing-impact, unclear-steps, severity-inflation, known-informational, or already-mitigated red flags.

---

## Relationship to adversarial review

This 7-question gate is a **pre-submit self-check** — it runs before the
finding enters the adversarial pipeline. It does not replace, and is not
replaced by, the **10-question adversarial review** in
`agents/finding-checker.md`, which runs blind (no engagement context) and
produces the canonical verdict (ACCEPTED / STALL / KILLED).

The two are complementary:
- **This gate** catches obvious deficiencies early, saving a round-trip
  through the adversarial pipeline.
- **The finding-checker** independently stress-tests evidence and claims
  without the operator's context or reasoning.

See `references/verdict-status-mapping.md` for how verdicts map to
`FindingStatus` transitions in the engine.
