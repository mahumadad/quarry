---
name: email-harvesting
description: >
  Harvest organizational email addresses and verify them: theHarvester sweeps, Hunter.io
  pattern derivation, and SMTP-level verification. Use after osint/dns-enumeration to build
  a confirmed employee-email list for phishing-susceptibility assessment or as input to
  credential-related testing explicitly covered by the RoE. Do NOT use for sending actual
  phishing emails or any live social-engineering action — that requires its own explicit
  RoE authorization and is outside this skill's scope.
metadata:
  type: recon
  phase: recon
  tools: [theHarvester, hunter.io, smtp-user-enum, swaks]
depends_on: [osint, dns-enumeration]
feeds_into: [github-dorking]
---

## Signals

- Need a confirmed list of valid organizational emails for phishing-risk assessment or
  authorized credential-testing (per RoE).
- Have employee names from `osint` but no confirmed email format/addresses.
- MX records from `dns-enumeration` are in hand and SMTP-level verification is in scope.

## Prerequisites

- Employee names from `osint`.
- MX records from `dns-enumeration`.
- RoE explicitly covers email harvesting / phishing-susceptibility testing (this touches
  real people's identifying information — confirm authorization scope, not just domain scope).

## Methodology

1. theHarvester sweep across its email-relevant sources:
   ```bash
   theHarvester -d example.com -b all -l 500 -f harvester-emails
   ```
2. Derive the organization's email naming pattern from confirmed examples (e.g. from
   theHarvester hits, LinkedIn, or public contact pages):
   ```
   Observed: jane.doe@example.com, john.smith@example.com → pattern: first.last@example.com
   ```
3. Hunter.io for pattern confirmation and additional discovered addresses (API key required;
   use the client's own account/key where the engagement provides one):
   ```bash
   curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=$HUNTER_KEY" | jq '.data.pattern, .data.emails[].value'
   ```
4. Generate candidate addresses for known employee names using the confirmed pattern, then
   verify via SMTP (RCPT TO probing) rather than guessing — low and slow, since aggressive
   SMTP probing can trip spam/abuse detection on the mail server:
   ```bash
   smtp-user-enum -M RCPT -D example.com -u candidate-users.txt -t mail.example.com
   ```
   Or manually with swaks for a single careful check:
   ```bash
   swaks --to jane.doe@example.com --from test@yourdomain.com --server mail.example.com -ehlo test --quit-after RCPT
   ```
5. Cross-reference confirmed emails against breach data from `osint`'s HIBP check to assess
   credential-reuse risk for those specific individuals.
6. Deliver the final list as: confirmed-valid emails, pattern-derived-unverified emails, and
   explicitly excluded (bounced/rejected) addresses — don't collapse these into one undifferentiated
   list, since confidence level matters for how the client should act on it.

## Tooling

`theHarvester -b all`, Hunter.io API (`domain-search`), `smtp-user-enum -M RCPT/VRFY/EXPN`,
`swaks` for manual single-target SMTP checks, `jq` for API response parsing.

## Validation gate

- [ ] RoE explicitly authorizes email harvesting / SMTP verification for this engagement —
      this is personal data about named individuals, not just a domain property.
- [ ] SMTP verification rate kept low per `opsec-discipline` — aggressive RCPT/VRFY probing
      reads as spam reconnaissance and can get the testing IP blacklisted.
- [ ] Output clearly separates confirmed-valid vs. pattern-derived-unverified addresses.
- [ ] Email list stored/transmitted only via the client's designated secure channel.

## Gotchas

- Many mail servers accept all RCPT TO addresses (catch-all) and report false "valid" for
  everything — confirm the server isn't a catch-all before trusting SMTP verification results
  (test with a deliberately nonsensical address first).
- VRFY/EXPN are disabled on most modern mail servers — RCPT-based verification is the
  reliable method now, not a fallback.
- Pattern-derived (unverified) addresses should never be presented to the client as confirmed
  valid — that's an Inferred/Unproven distinction just like any other finding.
- This data is about real employees — treat it with the same data-handling discipline as any
  other PII per `opsec-discipline`, regardless of how public the sources were.
