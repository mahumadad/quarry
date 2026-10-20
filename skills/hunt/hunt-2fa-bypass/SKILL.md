---
name: hunt-2fa-bypass
description: >
  Hunt for 2FA/MFA bypass: OTP brute force, response-manipulation bypass
  (status/field tampering), backup-code weaknesses, and session/flow
  issues that let an attacker skip or disable the second factor entirely.
  Use on any login flow with an OTP/TOTP/SMS/push second step. Keywords:
  2FA, MFA, OTP, TOTP, backup codes, bypass, response manipulation,
  step skipping.
  Do NOT use for the rate-limiting mechanics of the OTP endpoint itself in
  depth — use hunt-rate-limiting for the bypass techniques, this skill
  covers the rest of the 2FA-specific logic.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-287, CWE-304, CWE-308, CWE-330]
  mitre_attack: [T1556, T1621]
  tools: [burpsuite, curl, "Turbo Intruder"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-rate-limiting, hunt-session-management, hunt-password-reset]
---

## Signals

- Login flow with a distinct second step after password (OTP input screen, "check your phone" prompt).
- 2FA enrollment with backup/recovery codes offered.
- Multi-factor flow implemented as separate client-visible steps/endpoints rather than one atomic server-side decision.
- "Remember this device" / "trust this browser" option — potential bypass surface if the trust token is forgeable or over-broad.

## Prerequisites

- A disposable test account with 2FA enabled (TOTP app, SMS, or email-based — set up on your own test number/inbox).
- Burp Suite to intercept and manipulate each step of the flow independently.

## Methodology

1. **Map the exact flow.** Capture: (a) password submission response, (b) the 2FA challenge screen load, (c) OTP submission request/response, (d) final authenticated session issuance. Note every field in each response (status flags, "verified" booleans, redirect targets).

2. **Step-skipping — call the post-2FA endpoint directly.** After submitting correct credentials but *before* submitting the OTP, try requesting the authenticated area or the "set session as verified" endpoint directly:
   ```bash
   curl -s -i https://target.com/dashboard -b "session=$PARTIAL_SESSION"
   curl -s -i -X POST https://target.com/api/auth/2fa/skip -b "session=$PARTIAL_SESSION"
   ```

3. **Response manipulation.** If the 2FA check's result is evaluated client-side (SPA reads a JSON field like `{"2fa_required": true}` and decides whether to show the OTP screen), intercept the login response and flip the field before it reaches the client JS:
   ```bash
   # capture the real response first
   curl -s -i -X POST https://target.com/api/login -d "username=testuser&password=CorrectPass1!"
   # in Burp, use Repeater/match-replace to change "2fa_required":true -> false and
   # observe whether the SPA grants access without ever calling the OTP endpoint
   ```

4. **OTP brute force.** Submit the full space of a short numeric OTP (commonly 4–6 digits) in a tight loop, checking first whether hunt-rate-limiting bypass is needed:
   ```bash
   for code in $(seq -w 0 9999); do
     resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/api/auth/2fa/verify \
       -b "session=$PARTIAL_SESSION" -d "code=$code")
     [ "$resp" = "200" ] && echo "HIT: $code" && break
   done
   ```
   For realistic throughput, use Burp **Turbo Intruder** instead of sequential curl, respecting engagement rate/budget limits — this is inherently a high-request-count technique, confirm scope explicitly covers it.

5. **OTP leakage in response.** Check if the OTP-request step's own response (meant only to say "code sent") accidentally includes the code itself (common in staging/debug builds left enabled, or SMS-gateway mock responses):
   ```bash
   curl -s https://target.com/api/auth/2fa/request -b "session=$PARTIAL_SESSION" | jq
   ```

6. **Backup code weaknesses.** If backup/recovery codes are offered: check their format/entropy (are they short, numeric, sequential across accounts?), whether they're single-use and actually invalidated after use, and whether the backup-code redemption endpoint has the *same* rate limiting as the primary OTP endpoint (it's frequently weaker/forgotten):
   ```bash
   curl -s -i -X POST https://target.com/api/auth/2fa/backup-code -b "session=$PARTIAL_SESSION" -d "code=00000000"
   for i in $(seq 1 50); do
     curl -s -o /dev/null -w "%{http_code} " -X POST https://target.com/api/auth/2fa/backup-code \
       -b "session=$PARTIAL_SESSION" -d "code=$(printf '%08d' $i)"
   done; echo
   ```

7. **"Trust this device" token forgery/replay.** If the app sets a "remember me for 30 days, skip 2FA" cookie/token, check if it's a predictable value, works across different accounts, or isn't bound to a specific device fingerprint/IP at all:
   ```bash
   curl -s -i https://target.com/dashboard -b "session=$SESSION; trusted_device=$CAPTURED_TOKEN_FROM_OTHER_ACCOUNT"
   ```

8. **Race condition on OTP attempt counter.** Similar to hunt-rate-limiting's race technique, fire several guesses in parallel to see if the attempt-limiting counter can be outraced, allowing more guesses than the stated limit before lockout.

9. **Downgrade via alternate login path.** Check if a legacy/mobile/API login endpoint exists that doesn't enforce 2FA at all, while the main web login does:
   ```bash
   curl -s -i -X POST https://target.com/api/v1/login -d "username=testuser&password=CorrectPass1!"
   curl -s -i -X POST https://target.com/mobile-api/login -d "username=testuser&password=CorrectPass1!"
   ```

## Tooling

- Burp Suite Repeater + match/replace rules for response-field manipulation tests.
- Burp **Turbo Intruder** for realistic-throughput OTP brute force within authorized limits.
- `curl` for scripted multi-step flow replay and step-skipping tests.

## Root Causes

- 2FA enforcement decided client-side from a response flag, with the server issuing a fully authenticated session before (or regardless of) OTP verification.
- OTP endpoint has weaker or no rate limiting compared to the primary password login endpoint.
- Backup codes generated with low entropy, not invalidated after use, or checked against a separate code path that lacks the primary flow's protections.
- "Trusted device" token is a static/guessable value not bound to device+account, or not expiring.
- Multiple login entry points (web/mobile/API/legacy) with inconsistent 2FA enforcement.

## Validation Gate (minimum proof)

- Step-skip/response-manipulation: request/response sequence showing a fully authenticated session obtained without ever submitting a valid OTP.
- OTP/backup-code brute force: the actual successful guess with its position in the attempted sequence and total requests sent — don't claim feasibility without a completed run (on your own test account) showing the real attempt count required.
- Trusted-device bypass: proof the same token value grants access on a different account/session than the one it was issued for.
- Always note whether MFA was fully bypassed (0 factors effectively required) vs. weakened (easier but not trivial) — these are different severities.

## Gotchas

- **Minimum proof:** finding a `2fa_required` flag in a JSON response is not itself a bypass — you must prove the SPA/app actually grants access when that flag is flipped, end to end.
- **Common N/A:** server-side session state machine that only marks a session "fully authenticated" after independent OTP verification, with the OTP-skip/direct-dashboard-access attempts cleanly failing — close as N/A after testing both the step-skip and response-manipulation angles.
- **Overclaim trap:** demonstrating OTP brute force is "theoretically possible" for a 6-digit code without actually completing a feasible-throughput attempt (and hitting the real rate limiter) overstates the finding — tie the claim to the actual rate-limiting behavior observed (chain with hunt-rate-limiting).
- TOTP-based 2FA (app-generated, time-based) cannot be brute-forced the same way as a static SMS/email OTP — confirm which type is in use before choosing a technique.
- Respect engagement budget: full brute-force space exhaustion is expensive — prove feasibility with a bounded sample and rate-limit behavior observation rather than running to completion unless scope/time explicitly allows it.

## Chains & Compositions

- Weak/no rate limiting on OTP endpoint → chain fully with hunt-rate-limiting for the bypass-the-limiter technique, then return here for the OTP-space feasibility argument.
- Response-manipulation bypass → often co-occurs with poor session-state design, chain with hunt-session-management for how the "partial" vs "full" session is tracked.
- Backup code reuse/weak entropy → direct account takeover path, especially damaging when combined with a password-reset flow that also emails/displays backup codes (chain with hunt-password-reset).
- Legacy/alternate login path skipping 2FA entirely → the strongest, simplest bypass when present; always check for it first.
