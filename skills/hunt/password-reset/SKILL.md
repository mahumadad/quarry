---
name: password-reset
description: >
  Hunt for password reset flaws: predictable/weak reset tokens, Host-
  header-poisoned reset links, email/username parameter pollution that
  redirects the reset to an attacker-controlled address, and missing
  token invalidation/expiry. Use on any "forgot password" / account
  recovery flow. Keywords: password reset, reset token, forgot password,
  token entropy, token expiry, email parameter pollution, account
  recovery.
  Do NOT use for the Host-header injection mechanics themselves in depth
  — those live in host-header; this skill covers the rest of the
  reset-flow logic and composes with that one for the full chain.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-640, CWE-330, CWE-620]
  mitre_attack: [T1098, T1110]
  tools: [burpsuite, curl, "Burp Sequencer"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [host-header, rate-limiting, session-management]
---

## Signals

- "Forgot password" link present anywhere in the login flow.
- Reset link format reveals a token in the URL (`?token=`, `?code=`, `?key=`) — note its length/charset for entropy assessment.
- Reset request accepts `email` as a parameter in the body/query (vs. a session-independent lookup), opening pollution possibilities.
- Multi-step reset (request → email link → set new password) where each step's binding to the *same* request isn't obviously enforced.

## Prerequisites

- A disposable test account and access to its inbox.
- Ability to request many reset tokens for the same test account in sequence, for entropy/predictability analysis — Burp **Sequencer** is the standard tool for this.

## Methodology

1. **Capture the full flow.** Request a reset for your test account, record the exact token delivered, and the exact request used to redeem it (`POST /reset-password` with `token` + `new_password`).

2. **Token entropy/predictability.** Request 20–50 reset tokens in a row for the same account (respecting rate limits/budget) and feed them to Burp **Sequencer** for randomness analysis:
   ```bash
   for i in $(seq 1 30); do
     curl -s -X POST https://target.com/forgot-password -d "email=testuser@yourdomain.com"
     sleep 1
   done
   # collect the tokens from your test inbox, then load them into Burp Sequencer
   # (Burp > Sequencer > paste tokens > Analyze) for a bit-level randomness report
   ```
   Also check manually for obvious patterns: timestamp-based, sequential, derived from predictable user data (email hash with no salt, user ID + fixed string):
   ```bash
   echo -n "testuser@yourdomain.com" | md5sum   # does the token match a simple hash of known data?
   ```

3. **Token expiry.** Wait past the stated/assumed expiry window (or check documentation/UI copy for the stated window) and attempt to redeem an old token:
   ```bash
   curl -s -i -X POST https://target.com/reset-password -d "token=$OLD_TOKEN&new_password=NewPass123!"
   ```

4. **Token single-use enforcement.** Successfully reset a password once, then try reusing the same token again:
   ```bash
   curl -s -i -X POST https://target.com/reset-password -d "token=$USED_TOKEN&new_password=AnotherPass456!"
   ```

5. **Token invalidation on request of a new one.** Request a second reset token; confirm the first token is now invalid (many apps fail to invalidate older outstanding tokens):
   ```bash
   curl -s -X POST https://target.com/forgot-password -d "email=testuser@yourdomain.com"   # token2 issued
   curl -s -i -X POST https://target.com/reset-password -d "token=$TOKEN1&new_password=Pwned123!"  # should fail
   ```

6. **Email parameter pollution / IDOR on the reset request.** Test whether supplying multiple `email` values, or an array, or a secondary identifying field (`user_id`) lets you redirect the reset to an account you don't own, or trigger it for a victim while receiving the token yourself:
   ```bash
   curl -s -i -X POST https://target.com/forgot-password -d "email=victim@target.com&email=attacker@yourdomain.com"
   curl -s -i -X POST https://target.com/forgot-password -H "Content-Type: application/json" \
     -d '{"email":["victim@target.com","attacker@yourdomain.com"]}'
   curl -s -i -X POST https://target.com/forgot-password -d "email=victim@target.com&user_id=<attacker_own_id>"
   ```

7. **Response-based account enumeration.** Check whether the forgot-password response (or timing) differs between an existing and a non-existing email, which, combined with weak rate limiting, enables user enumeration:
   ```bash
   curl -s -i -X POST https://target.com/forgot-password -d "email=definitely-not-registered-$(date +%s)@test.com"
   curl -s -i -X POST https://target.com/forgot-password -d "email=testuser@yourdomain.com"
   # diff response body/length/timing
   ```

8. **Host-header-based poisoning** (cross-reference, run the actual technique from host-header): confirm whether the reset link's domain is derived from the request's Host — if so, this flow's token can be exfiltrated to an attacker domain. Test all proxy-related headers, not just `Host`:
   ```bash
   for hdr in "Host: evil.test" \
              "X-Forwarded-Host: evil.test" \
              "X-Original-Host: evil.test" \
              "X-Forwarded-Server: evil.test" \
              "Forwarded: host=evil.test"; do
     curl -s -X POST https://target.com/forgot-password \
       -H "$hdr" -d "email=testuser@yourdomain.com"
   done
   # check test inbox: any reset link pointing to evil.test = confirmed poisoning
   ```
   Many reverse-proxy setups (nginx, Apache, Cloudflare) pass `X-Forwarded-Host` through even
   when `Host` is locked. Frameworks that rebuild URLs from request headers (Django's
   `get_host()`, Laravel's `url()`, Rails `request.host`) often trust these headers by default.

9. **Password strength/reuse check after reset.** Confirm the new password set via reset is subject to the same strength policy as normal signup (sometimes the reset endpoint is a legacy path with weaker validation).

## Tooling

- Burp **Sequencer** for statistical token randomness analysis (the standard way to substantiate a "predictable token" claim rather than eyeballing a few samples).
- `curl` for scripted token request/redemption cycles.
- A disposable mailbox (your own test domain) to receive tokens programmatically if automating entropy collection.

## Root Causes

- Reset token generated from a weak PRNG, a predictable seed (timestamp, user ID, email hash without a secret/salt), or insufficient length/entropy.
- Token not invalidated after use, after a new token is issued, or after expiry.
- Reset request endpoint accepts attacker-influenceable routing of the token (parameter pollution, Host header) without binding to a single validated identity.
- No distinction in server response/timing between existing and non-existing accounts (enumeration).

## Validation Gate (minimum proof)

- Entropy: Burp Sequencer's statistical report (or equivalent) showing materially less than the expected bits of entropy for the token length/charset — a token that "looks random" to the eye is not proof; run the actual analysis.
- Expiry/reuse: request/response pair showing a token redeemed successfully outside its stated window or more than once.
- Parameter pollution: request/response showing the token delivered to or usable by an identity other than the one that should have received it, on your own two test accounts.
- Enumeration: side-by-side response diff (body/length/timing) for existing vs. non-existing accounts, captured multiple times to rule out noise.

## Gotchas

- **Minimum proof:** "the token looks short" or "looks like base64 of a timestamp" is a hypothesis — run the Sequencer analysis or demonstrate an actual successful prediction before calling it Demonstrated.
- **Common N/A:** tokens are high-entropy (128+ bit, CSPRNG-backed, e.g. a UUIDv4 or signed JWT with short expiry and server-side revocation) and single-use/expiring correctly — close as N/A after verifying all three properties, not just one.
- **Overclaim trap:** finding that reset tokens are UUIDs (which look "random") is not itself a finding — UUIDv4 is generally fine entropy-wise; the real risks are expiry/reuse/pollution, which you must test independently.
- Account enumeration via response differences is often accepted as very-low/informational risk by many orgs (balances UX vs. security) — don't inflate severity without checking if it meaningfully combines with the rate-limiting gaps found in rate-limiting.
- Mail delivery delay can make expiry testing slow — plan test timing accordingly within the project's timeout budget.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Token predictability/reuse** — Is the reset token predictable, reusable after use, or valid for an unbounded time?
2. **Host header poisoning chain** — Can the reset link's domain be poisoned via Host header injection to redirect to an attacker-controlled domain?
3. **Account takeover via email parameter tampering** — Can you request a reset for one account but have the token delivered to an attacker-controlled address (IDOR in the reset request)?
4. **Rate limiting on token guessing** — Is there rate limiting on reset-token submission, enabling brute force of a short/numeric token?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Host-header-poisoned reset link + weak Referrer-Policy → full token exfiltration, chain fully with host-header.
- Predictable/weak token + no rate limiting on redemption attempts → brute-forceable account takeover, chain with rate-limiting.
- Successful reset → new session issued — check session-management for whether old sessions are properly invalidated after a password reset (a common separate gap).
- Email parameter pollution → direct account takeover without needing to defeat token entropy at all.
