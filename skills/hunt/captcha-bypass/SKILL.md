---
name: captcha-bypass
description: >
  Hunt for CAPTCHA/anti-automation controls that can be defeated without solving the challenge:
  token omitted and still accepted, token replayed across requests, verification done only in the
  browser, a fixed/guessable success response, or a race in the redeem step. Use when a CAPTCHA
  (reCAPTCHA, hCaptcha, Turnstile, a custom image/math challenge) guards login, signup, password
  reset, checkout, contact/abuse-prone forms, or any rate-limited action. Keywords: captcha bypass,
  recaptcha, hcaptcha, turnstile, g-recaptcha-response, cf-turnstile-response, client-side
  validation, token reuse, anti-automation, bot protection, siteverify.
  Do NOT use for the rate-limiting control itself (missing/weak throttling) — use rate-limiting;
  this skill is specifically about the CAPTCHA gate being non-functional.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-804, CWE-287, CWE-799]
  mitre_attack: [T1110, T1111]
  tools: [curl, burp, ffuf, python-requests]
depends_on: [active-recon, web-crawling, auth-bypass]
feeds_into: [chain-analysis, rate-limiting, credential-testing]
chains_with: [auth-bypass, password-reset, business-logic]
---

## Signals

- A form that renders a CAPTCHA widget but the sensitive action (login, OTP request, reset,
  coupon redeem, vote, signup) is served by a separate JSON/API endpoint — check whether that
  endpoint enforces the token or just the browser does.
- Response to the gated action succeeds when you strip the `g-recaptcha-response` /
  `cf-turnstile-response` / `h-captcha-response` field entirely, or send it empty/`undefined`.
- The same token value works on a second, third, Nth request — provider tokens are single-use;
  reuse acceptance means the server never calls `siteverify` (or ignores its `success:false`).
- The challenge is custom (server renders "What is 3+4?" or a distorted-text image) and the
  expected answer, the answer hash, or a `captcha_id→answer` mapping is present in the page
  source, a cookie, a hidden field, or a prior API response.
- Widget present on page load but absent from the actual XHR/fetch payload (DevTools Network) —
  purely decorative.
- A `verify`/`validate` endpoint that returns a boolean the client trusts, callable directly.

## Prerequisites

- An identified gated action and its real backend request captured (method, path, body, headers,
  the exact CAPTCHA parameter name).
- A baseline: one legitimate solved submission captured so you know the success-vs-failure
  response shapes.
- For race testing: the ability to fire concurrent requests (Burp Turbo Intruder, `ffuf`,
  or a small threaded script).

## Methodology

1. **Locate the enforcement boundary.** Submit the form once legitimately and capture the backend
   request. Identify which field carries the CAPTCHA token and whether the browser does any
   pre-submit gating (disabled button) that the API does not replicate.

2. **Omission test — is the token even required server-side?**
   ```bash
   # Replay the captured action with the CAPTCHA field removed entirely
   curl -s -X POST https://target/api/login \
     -H "Content-Type: application/json" \
     -d '{"email":"a@b.test","password":"x"}'          # no g-recaptcha-response at all
   # Then with it present-but-empty and present-but-garbage:
   curl -s -X POST https://target/api/login -H "Content-Type: application/json" \
     -d '{"email":"a@b.test","password":"x","g-recaptcha-response":""}'
   curl -s -X POST https://target/api/login -H "Content-Type: application/json" \
     -d '{"email":"a@b.test","password":"x","g-recaptcha-response":"AAAA"}'
   ```
   If the action proceeds (reaches the auth/business logic, not a "captcha required" error), the
   gate is not enforced. Distinguish "captcha missing" rejection from "wrong password" rejection.

3. **Replay/reuse test.** Solve the CAPTCHA once in the browser, grab the fresh token, and submit
   it twice (or N times) back-to-back:
   ```bash
   TOK='03AGdBq25...'   # single real token from a browser solve
   for i in 1 2 3; do
     curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target/api/login \
       -H "Content-Type: application/json" \
       -d "{\"email\":\"a@b.test\",\"password\":\"x\",\"g-recaptcha-response\":\"$TOK\"}"
   done
   ```
   Provider `siteverify` burns a token on first use; any 2nd+ acceptance proves the server is not
   calling it (or caches/ignores the result). One solve then unlimited automated submissions.

4. **Client-only validation.** For custom challenges, diff the page/JS: search for the answer,
   an answer hash, or a client-side `if (userAnswer === expected)` gate. Check whether the
   success path can be reached by calling the post-CAPTCHA endpoint directly with a forged
   "captcha_passed":true flag or a reused session attribute.
   ```bash
   # grep the delivered JS for the comparison / embedded answer
   curl -s https://target/static/app.js | grep -iE "captcha|answer|solved|verify" 
   ```

5. **Fixed/guessable response.** If the challenge is a small space (math under 100, 4-digit
   numeric, a fixed MD5 list), enumerate it. If the server accepts a constant `captcha=0000` or
   the answer is derivable from a `captcha_id`, that's a deterministic bypass — show the mapping.

6. **Race on redeem.** When the CAPTCHA token is valid-once but the guarded action (e.g. "apply
   one signup bonus") is checked separately, fire concurrent requests with the same token to beat
   the invalidation window:
   ```bash
   # Burp Turbo Intruder / threaded requests sharing one fresh token
   # measure how many of N parallel requests with the same token succeed
   ```
   Any count >1 is a TOCTOU in the redeem path (overlaps with race-condition).

## Tooling

- Burp Suite (Repeater for omission/reuse, Turbo Intruder for the redeem race).
- `curl` / threaded `python-requests` for scripted replay and concurrency.
- Browser DevTools Network tab — to capture the real backend request and confirm the widget is
  or isn't in the payload.
- `ffuf` for enumerating small custom-challenge answer spaces.
- A single manual browser solve to source one legitimate token (never automate solving the
  provider challenge — that is out of scope and usually a ToS violation).

## Root Causes

- Server renders the widget but never calls the provider's `siteverify` endpoint — trusts the
  presence of a (any) token, or the browser's gating alone.
- `siteverify` is called but its `success:false` / `error-codes` result is not checked, or the
  call is wrapped in a `try/except` that fails open.
- Token treated as a reusable secret instead of single-use; no binding to the specific
  request/action/session, no expiry enforcement.
- Custom challenge with the answer computable client-side, stored in a predictable field, or
  drawn from a tiny keyspace.
- CAPTCHA verified on one endpoint but the sensitive effect committed on another that skips it.

## Validation Gate (minimum proof)

- **Demonstrated:** the gated action completes (reaches/triggers its real effect — auth attempt
  accepted, OTP sent, reset issued, bonus applied) via a request that carries no valid, fresh,
  single-use CAPTCHA token. Show the request (no/empty/reused/forged token) and the success
  response, repeated to rule out a one-off. For reuse, show the token succeeding ≥2 times.
- **Inferred:** server accepts a malformed/empty token in a way that *suggests* no `siteverify`,
  but the underlying action is otherwise blocked (e.g. still rejected on credentials) so full
  automation isn't shown; or the answer is visible client-side but end-to-end submission not yet
  driven.
- **Unproven:** "the widget looks decorative" / "probably client-side only" with no replayed
  request demonstrating acceptance. Do not report.
- State the concrete abuse unlocked (credential stuffing, OTP/SMS flooding, mass signup, vote
  stuffing) — the CAPTCHA bypass matters only as the enabler of that downstream abuse.

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| Token omission | drop `g-recaptcha-response` field entirely | test if any token is required server-side |
| Empty token | `"g-recaptcha-response":""` | catch "field present" checks that skip value validation |
| Garbage token | `"g-recaptcha-response":"AAAA"` | force a real `siteverify` to fail; if accepted, not verified |
| Token reuse | one fresh token → submit N times | prove `siteverify` single-use is not enforced |
| Forged flag | `"captcha_verified":true` / `"human":1` | reach post-CAPTCHA logic via a trusted client flag |
| Fixed answer | custom math/numeric from tiny keyspace | enumerate deterministic answer |
| Cross-endpoint | solve on `/verify`, commit on `/action` | hit the effect endpoint that skips the gate |

```bash
# Detection: does the token actually matter? Compare success across token states.
BASE='{"email":"probe@t.test","password":"wrongpass"}'
for variant in 'no_token' 'empty' 'garbage'; do
  case $variant in
    no_token) BODY="$BASE" ;;
    empty)    BODY='{"email":"probe@t.test","password":"wrongpass","g-recaptcha-response":""}' ;;
    garbage)  BODY='{"email":"probe@t.test","password":"wrongpass","g-recaptcha-response":"ZZZZ"}' ;;
  esac
  code=$(curl -s -o /tmp/r.$variant -w "%{http_code}" -X POST https://target/api/login \
    -H "Content-Type: application/json" -d "$BODY")
  echo "$variant -> $code : $(grep -io 'captcha' /tmp/r.$variant | head -1 || echo no-captcha-error)"
done
# If none of the variants returns a 'captcha required' error (only credential errors),
# the CAPTCHA is not enforced on this endpoint.
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| "field must be present" | send empty string or null | passes presence check, no value check |
| provider `siteverify` single-use | token replay before cleanup | works only if server never calls siteverify or caches success |
| browser-side button gating | call backend endpoint directly | widget never reaches the API payload |
| custom image/math challenge | read embedded answer / enumerate keyspace | answer in JS, cookie, hidden field, or <100 math space |
| per-page nonce + captcha | reuse nonce+token pair concurrently | TOCTOU in redeem (see race-condition) |
| server verifies on `/verify` only | commit on sibling `/action` endpoint | enforcement/effect split |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Credential stuffing / brute force** — With the gate down on login, is throttling also weak?
   Chain into rate-limiting / credential-testing for actual account compromise.
2. **OTP / SMS / email flooding** — Does the unguarded endpoint send messages per request
   (cost abuse, user harassment)? Quantify messages per minute achievable.
3. **Mass account creation** — Signup without CAPTCHA → automated account farming → downstream
   fraud/spam; note any per-account resource grant.
4. **Password-reset abuse** — Unguarded reset request endpoint enables user enumeration or
   reset-token flooding (chain password-reset).
5. **Business-logic abuse** — Coupon/vote/referral redeem freed from the one-human gate; chain
   business-logic for quantified financial impact.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- CAPTCHA bypass + weak throttling → **rate-limiting** / **credential-testing** → account
  takeover at scale.
- CAPTCHA bypass on reset flow → **password-reset** (token flooding, enumeration) → **auth-bypass**.
- CAPTCHA bypass on signup → **business-logic** (referral/bonus farming, resource exhaustion).
- CAPTCHA token reuse race → **race-condition** (one solve, many committed effects).
- CAPTCHA bypass on contact/feedback form → **email-injection** / spam relay abuse.

## Gotchas

- **The bypass is only as valuable as what it ungates.** A defeated CAPTCHA on a harmless form is
  low severity; the finding's impact is the downstream abuse (stuffing, flooding, fraud) — prove
  that path or scope it honestly, don't inflate "CAPTCHA bypass" to Critical by itself.
- **Don't automate solving the provider challenge.** Using a solver service / ML to beat
  reCAPTCHA is both out of scope and not what proves the vuln — the vuln is that the *server*
  doesn't verify. Source tokens by solving once manually.
- **Distinguish rejection reasons.** A 403 could be the CAPTCHA gate OR a WAF OR bad creds. Pin
  down that the block is specifically the missing-token path, not an unrelated control.
- **Common N/A:** `siteverify` IS called and single-use IS enforced — omission/garbage/reuse all
  fail cleanly. Record as tested-and-robust, not a finding.
- **Enterprise reCAPTCHA / score-based:** no hard pass/fail; the server acts on a risk score.
  "Bypass" there means showing low-score traffic is still allowed through for a sensitive action
  — a policy finding, weaker than a binary-verification bypass; label precisely.
- **Turnstile/hCaptcha tokens are short-lived** (~minutes); a reuse test that fails might be
  expiry, not single-use enforcement — reuse immediately and also test an expired token to
  separate the two controls.
