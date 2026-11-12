---
name: security-policy-parser
description: >
  Parse and extract actionable constraints from a target's bug bounty or
  vulnerability disclosure policy before planning any testing phase. Identifies:
  test account policy (provided vs. researcher-owned), explicit exclusions,
  SLA/payment terms, safe harbor language, and scope boundaries that affect
  engagement planning. Use after scope is defined and before recon begins.
  Keywords: bug bounty policy, VDP, vulnerability disclosure, scope rules,
  test accounts, safe harbor, responsible disclosure, program rules.
metadata:
  type: engage
  phase: scoping
  tools: [curl, jq]
depends_on: [scope-discipline]
feeds_into: [passive-recon, identity-map]
---

## Signals

- Engagement targeting a bug bounty or VDP program.
- Need to determine whether authenticated testing is feasible before
  starting recon (credential availability affects phase planning).
- Need to confirm safe harbor, exclusions, and reporting requirements.

## Prerequisites

- URL of the target's security/bug-bounty policy (from `scope-discipline`
  or the engagement brief).

## Methodology

1. **Fetch the policy page:**
   ```bash
   curl -s "https://target.example.com/security-policy" > policy-raw.html
   # strip HTML for readable text
   lynx -dump -nolist policy-raw.html > policy-text.txt
   # or
   cat policy-raw.html | sed 's/<[^>]*>//g' | tr -s ' \n' > policy-text.txt
   ```

2. **Extract key fields** — search for these patterns:

   | Field | Search terms | Impact on engagement |
   |-------|-------------|---------------------|
   | Test accounts | "own account", "test account", "we provide", "sandbox" | Determines if auth testing needs coordination |
   | Exclusions | "out of scope", "excluded", "do not", "prohibited" | Hard limits on techniques |
   | Safe harbor | "legal action", "law enforcement", "good faith" | Engagement risk assessment |
   | Rewards | "$", "bounty", "reward", "payment" | ROI estimation |
   | SLA | "business days", "response time", "triage" | Reporting timeline |
   | Reporting format | "encrypt", "PGP", "format", "steps to reproduce" | Report template requirements |
   | Domains | "in scope", "*.domain", "assets" | Cross-check against scope.txt |

3. **Produce a policy summary** — structured output for the engagement
   state:
   ```
   ## Policy Summary: [Target]
   - **URL:** [policy URL]
   - **Last updated:** [date if stated]
   - **Safe harbor:** [yes/no + quote]
   - **Test accounts:** [provided / researcher-owned / unclear]
   - **Account creation path:** [self-service / sales / invitation / unclear]
   - **Exclusions:** [list]
   - **Reward tiers:** [table]
   - **SLA:** [triage days / payment days]
   - **Report requirements:** [encryption, format, etc.]
   - **Domains in scope:** [list, cross-checked with scope.txt]
   ```

4. **Flag blockers for phase planning:**
   - If test accounts = "researcher-owned" AND no self-service signup
     exists → flag that authenticated testing requires commercial
     onboarding or vendor coordination BEFORE planning auth phases.
   - If exclusions mention specific techniques (e.g., "no automated
     scanning") → annotate in scope.json rules.
   - If rewards are $0 (VDP only) → adjust ROI expectations.

5. **Store in engagement state:**
   Save the summary as `report/policy-summary.md` and update
   `.pentest-state/scope.json` with any rules extracted.

## Validation Gate

- [ ] Policy URL fetched and readable text extracted.
- [ ] Test account availability determined (provided / own / unclear).
- [ ] All exclusions captured and reflected in scope rules.
- [ ] Safe harbor language confirmed present (or its absence noted as
      engagement risk).
- [ ] Account creation path documented — if no self-service, the blocker
      is flagged before recon completes.

## Gotchas

- Policies change. Always fetch fresh at engagement start — don't rely on
  cached or remembered versions.
- "Use your own account" does NOT mean "create an account for free" — if
  there's no self-service signup, the researcher must subscribe or
  coordinate with the vendor. This distinction blocked authenticated
  testing in the Healthatom engagement for 8+ phases.
- Some policies list assets in a machine-readable format (JSON, YAML in
  `.well-known/security.txt` or HackerOne scope API). Prefer structured
  sources over scraping HTML.
- "Web/API vulnerabilities" in scope usually covers AI/ML endpoints too,
  but confirm if there's ambiguity.
- VDPs (no reward) still provide safe harbor — the legal protection has
  value even without payment.

## Chain Anchors

Policy analysis feeds into:
1. **Engagement planning** — credential strategy, phase ordering
2. **Report formatting** — match the program's expected format
3. **ROI estimation** — reward tiers × finding severity × competition
