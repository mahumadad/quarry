---
name: session-management
description: >
  Hunt for session management flaws: session fixation, predictable/weak
  session tokens, improper expiration (logout/timeout not invalidating
  server-side), and unlimited/unmanaged concurrent sessions. Use on any
  app using cookie- or token-based sessions post-authentication. Keywords:
  session fixation, session prediction, session expiration, concurrent
  sessions, logout invalidation, JWT, session token entropy.
  Do NOT use for the OAuth/OIDC token issuance flow itself — use oauth.
  Do NOT use for CSRF token specifics unless the session token doubles as
  the CSRF token (note the overlap, chain accordingly).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-384, CWE-330, CWE-613, CWE-287]
  mitre_attack: [T1539, T1550.004]
  tools: [burpsuite, "Burp Sequencer", curl, jwt_tool]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [oauth, 2fa-bypass, password-reset, clickjacking]
---

## Signals

- Session identifier delivered as a cookie (`Set-Cookie: session=...`) or bearer token (JWT or opaque) after login.
- Session cookie set/visible *before* authentication (on the initial page load) — candidate for fixation if it's reused post-login rather than rotated.
- "Log out of all devices" / active sessions list feature present (or conspicuously absent).
- JWT used as the session token (three base64 segments separated by `.`).
- No visible absolute session timeout communicated anywhere (just inactivity-based, or none at all).

## Prerequisites

- Two browser contexts/test accounts to test fixation (attacker sets token, victim test account logs in) and concurrent-session behavior.
- Access to inspect raw `Set-Cookie` headers across the full auth lifecycle (pre-login, post-login, post-logout, post-password-change).

## Methodology

1. **Session fixation.** Capture the pre-login session cookie value, then complete login, and check whether the **same** cookie value persists or whether a new one is issued:
   ```bash
   # pre-login
   curl -s -i -c cookies_pre.txt https://target.com/ | grep -i set-cookie
   # attacker "plants" that pre-login session id on a victim by sending them a link
   # that forces this exact cookie value (session-id-in-URL apps, or a subdomain
   # cookie-setting XSS/CRLF elsewhere — see crlf-injection for the planting vector)
   curl -s -i -b cookies_pre.txt -X POST https://target.com/login -d "username=testuser&password=CorrectPass1!" | grep -i set-cookie
   ```
   If the session ID value from `cookies_pre.txt` is identical before and after login, the app is vulnerable to fixation: an attacker who gets a victim to use an attacker-known pre-auth session value, then has the victim log in, ends up sharing that now-authenticated session.

2. **Session token entropy/predictability.** For opaque tokens, collect 20–50 fresh session IDs (new login each time, or new pre-auth session each time) and run them through Burp **Sequencer**:
   ```bash
   for i in $(seq 1 30); do
     curl -s -c - https://target.com/ -o /dev/null | grep -i session
   done
   # feed the collected values into Burp Sequencer for a randomness/entropy report
   ```
   For JWTs, check the signing algorithm and whether `alg: none` or key confusion (RS256→HS256) is accepted:
   ```bash
   jwt_tool $TOKEN -T
   # try alg=none tampering
   jwt_tool $TOKEN -X a
   # try HS256/RS256 confusion using the server's own public key as the HMAC secret
   jwt_tool $TOKEN -X k -pk server_public_key.pem
   ```

3. **Session expiration — logout invalidation.** Log in, capture the session token, log out via the UI, then replay the **same** token against an authenticated endpoint:
   ```bash
   curl -s -i https://target.com/api/me -b "session=$TOKEN_AFTER_LOGOUT"
   # 200 with valid data after logout = server-side session not invalidated
   ```

4. **Session expiration — password change invalidation.** Change the account password, then check whether a session token obtained *before* the change still works:
   ```bash
   curl -s -i https://target.com/api/me -b "session=$OLD_TOKEN_BEFORE_PW_CHANGE"
   ```

5. **Absolute/idle timeout.** Leave a valid session idle and probe periodically to find the actual enforced timeout (or confirm there isn't one):
   ```bash
   sleep 3600; curl -s -i https://target.com/api/me -b "session=$TOKEN"
   ```
   For JWTs, decode `exp`/`iat` claims directly instead of waiting:
   ```bash
   echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.exp - .iat'   # lifetime in seconds
   ```

6. **Concurrent session handling.** Log in from two separate contexts (simulating two devices) with the same account and check whether both sessions remain valid simultaneously, and whether the account holder is notified:
   ```bash
   curl -s -i https://target.com/api/me -b "session=$TOKEN_DEVICE_A"
   curl -s -i https://target.com/api/me -b "session=$TOKEN_DEVICE_B"
   ```
   If a "log out all other sessions" feature exists, verify it actually invalidates the other token server-side (not just removes it from a UI list):
   ```bash
   curl -s -X POST https://target.com/api/sessions/revoke-others -b "session=$TOKEN_DEVICE_A"
   curl -s -i https://target.com/api/me -b "session=$TOKEN_DEVICE_B"   # should now fail
   ```

7. **Cookie attribute hardening check.** Inspect `Secure`, `HttpOnly`, `SameSite` on the session cookie — missing attributes don't directly cause the above flaws but materially raise their impact (e.g. fixation + no `HttpOnly` = trivially stealable via any XSS elsewhere):
   ```bash
   curl -s -i https://target.com/login -c - | grep -i set-cookie
   ```

## Tooling

- Burp **Sequencer** for statistical session-token entropy analysis.
- `jwt_tool` for JWT structural/algorithm attacks (`alg:none`, key confusion, weak-secret brute force via `-C` with a wordlist).
- `curl -c`/`-b` for scripted cookie-jar lifecycle testing across login/logout/password-change.

## Root Causes

- Session ID assigned at first page load (pre-auth) and never regenerated on successful login (classic fixation root cause).
- Session store (server-side) not actually consulted on logout — logout only clears the client-side cookie, the token remains valid against the backend.
- Session tokens generated with insufficient entropy or derived from predictable inputs.
- No session revocation list / short-lived-token-with-refresh architecture, so a JWT remains valid for its full stated lifetime regardless of logout or password change.
- No enforced cap or visibility on concurrent sessions per account.

## Validation Gate (minimum proof)

- Fixation: request/response pair showing the identical session value spans pre-login and post-login states, plus (ideally) a full demonstration that a second party (your own second test context) using that pre-known value is authenticated as the account that logged in.
- Logout/password-change invalidation: the exact request made with the "old" token succeeding (200 + real data) *after* the invalidating action was completed and confirmed (e.g. logout response received, or password-change 200 received) before the replay attempt.
- Entropy: Sequencer's statistical report, not a visual guess.
- JWT: the tampered token's full value and the server's response proving it was accepted as valid.

## Gotchas

- **Minimum proof:** a session cookie that merely *looks* unchanged across requests within the same already-authenticated session is normal and not fixation — the test specifically requires capturing the value *before* authentication and confirming it survives *through* authentication.
- **Common N/A:** app rotates the session ID on every privilege change (login, logout, password change) and maintains a server-side revocation/session store consulted on every request — closes fixation and most expiration gaps at once; verify this is actually the case, not just assumed from "uses express-session" or similar.
- **Overclaim trap:** a long JWT `exp` (e.g. 24h) is not automatically a finding — only report it if combined with no logout/password-change invalidation mechanism (stateless JWTs with no revocation are often an accepted design trade-off; the finding is the *lack of revocation on security events*, not the lifetime alone).
- Don't test concurrent-session/"log out all" features in ways that lock yourself out mid-engagement without a way back in — keep a spare authenticated session.
- `SameSite=Lax` is sufficient against most CSRF for navigational requests but not against all vectors — don't conflate cookie attribute hardening with the deeper session-lifecycle issues this skill targets.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Session fixation** — Can you fix a victim's session ID before login and gain access after they authenticate?
2. **Session not invalidated on logout/password change** — Does the old session token remain valid after logout or password change?
3. **Concurrent session / device binding gaps** — Can the same session token be used from multiple devices/locations without detection?
4. **Token leakage via URL/logs** — Does the session token appear in URLs, Referer headers, or logs, enabling theft?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Session fixation + any planting vector (CRLF-injected `Set-Cookie`, XSS on a sibling subdomain, subdomain takeover) → full account takeover; chain with crlf-injection or subdomain-takeover for the planting mechanism.
- Missing logout invalidation + a leaked token (via Referer, logs, browser history) → extended window of exploitability; chain with cache-poisoning or oauth if the token leaked through those vectors.
- Weak session entropy + no account lockout → brute-forceable session prediction, chain with rate-limiting for the feasibility argument.
- Session-state confusion between "partial" (pre-2FA) and "full" authentication → chain directly with 2fa-bypass.
