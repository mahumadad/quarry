---
name: hunt-oauth
description: >
  Hunt for OAuth2/OIDC implementation flaws: redirect_uri manipulation, state
  parameter CSRF, authorization code/token leakage via Referer or open
  redirect, scope escalation, and client confusion between apps sharing an
  Authorization Server. Use when the target has "Login with X", SSO, or any
  /authorize, /oauth/token, /oidc endpoint. Keywords: OAuth, OIDC, SSO,
  redirect_uri, state, PKCE, implicit flow, id_token, client_id.
  Do NOT use for session cookie handling post-login — use hunt-session-management.
  Do NOT use for JWT signature/alg attacks on the resulting token — use hunt-session-management
  for session tokens or a dedicated JWT skill if present.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-346, CWE-352, CWE-601, CWE-287]
  mitre_attack: [T1528, T1550]
  tools: [burpsuite, curl, jwt_tool, mitmproxy]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-host-header, hunt-session-management, hunt-crlf-injection]
---

## Signals

- Login button labeled "Continue with Google/Facebook/Microsoft/GitHub".
- Requests to `/authorize`, `/oauth2/authorize`, `/oidc/auth`, `.well-known/openid-configuration`.
- `redirect_uri`, `return_to`, `continue`, `state`, `client_id`, `scope`, `response_type` params in URLs.
- Multiple first-party apps sharing one Authorization Server (client confusion risk).
- `response_type=token` or `response_type=id_token` (implicit flow — token in URL fragment).

## Prerequisites

- An account on the OAuth client app (or ability to register one) to observe the full flow.
- A proxy (Burp/mitmproxy) capturing traffic across the redirect chain, including the fragment (`#`) which proxies normally don't log — use browser history or an attacker-controlled endpoint to capture it.
- A domain/endpoint you control to receive leaked codes/tokens via Referer or redirect_uri substitution (e.g. a Burp Collaborator / webhook.site URL).

## Methodology

1. **Map the flow.** Pull the OIDC discovery doc to enumerate endpoints and supported flows:
   ```bash
   curl -s https://idp.target.com/.well-known/openid-configuration | jq
   ```
   Capture a full legitimate login in Burp (Proxy > HTTP history), note the exact `/authorize` request and every parameter.

2. **Test redirect_uri validation strictness.** Replay the `/authorize` request with variations and check if the IdP still redirects/issues a code:
   ```bash
   # exact match bypass attempts
   curl -s -i "https://idp.target.com/authorize?client_id=X&redirect_uri=https://app.target.com.evil.com/cb&response_type=code&scope=openid&state=abc"
   curl -s -i "https://idp.target.com/authorize?...&redirect_uri=https://app.target.com/cb%2f..%2f..%2fevil"
   curl -s -i "https://idp.target.com/authorize?...&redirect_uri=https://app.target.com@evil.com/cb"
   curl -s -i "https://idp.target.com/authorize?...&redirect_uri=https://evil.com/cb?https://app.target.com"
   curl -s -i "https://idp.target.com/authorize?...&redirect_uri=https://app.target.com/cb/../../../logout"
   ```
   Also try: subdomain the app itself doesn't control but is in-scope (`https://app.target.com/open-redirect-endpoint`), trailing slash mismatches, case changes, and registering a second `redirect_uri` query param (parser confusion — see hunt-parameter-pollution).

3. **Check for open redirect chaining.** If `redirect_uri` must match exactly but the matched path itself contains an open redirect (e.g. `/cb?next=`), code/token leaks via the second hop's Referer header to an external resource (images, analytics scripts) on the attacker page.

4. **Test `state` parameter for CSRF.** Start a login flow as attacker, capture the authorize URL before completing it, send that URL to a victim who is logged into their own account on the client app, and check whether the callback binds attacker's OAuth identity to victim's session (login CSRF / account linking takeover). Confirm the app validates `state` is bound to the browser session and is single-use:
   ```bash
   # replay the same authorization code twice
   curl -s -X POST https://idp.target.com/oauth2/token \
     -d "grant_type=authorization_code&code=CAPTURED_CODE&redirect_uri=https://app.target.com/cb&client_id=X&client_secret=Y"
   # repeat — should fail the second time
   ```

5. **Scope escalation.** Request broader scopes than the client normally asks for and see if the IdP grants them without consent re-prompt:
   ```bash
   curl -s -i "https://idp.target.com/authorize?client_id=X&redirect_uri=https://app.target.com/cb&response_type=code&scope=openid%20profile%20email%20admin%20offline_access&state=abc"
   ```
   Decode the resulting `access_token`/`id_token` (if JWT) and diff granted `scope`/`aud`/`roles` claims against what was requested:
   ```bash
   jwt_tool <token> -T   # inspect claims interactively
   echo '<token>' | cut -d. -f2 | base64 -d 2>/dev/null | jq
   ```

6. **Client confusion / mix-up attack.** If the same IdP serves multiple client_ids (multi-tenant SaaS), try submitting Client A's authorization code to Client B's token endpoint, or swap `client_id` while keeping victim's code — check whether the IdP validates the code was issued to that specific client+redirect_uri pair.

7. **Implicit flow fragment leakage.** If `response_type=token` or `id_token`, the token lands in the URL fragment of the redirect — any third-party script or beacon in the client page, or a browser extension, can read it. Check `Referer` leakage from the callback page to any embedded third-party resource:
   ```bash
   curl -s -i "https://idp.target.com/authorize?client_id=X&redirect_uri=https://app.target.com/cb&response_type=token&scope=openid&state=abc&nonce=1"
   ```

8. **PKCE downgrade.** If the client is public (SPA/mobile) and PKCE (`code_challenge`) is advertised as supported, try omitting `code_challenge` entirely — if the IdP still issues a code without it, code interception via a malicious app on the same device becomes viable.

## Tooling

- `burpsuite` (Proxy + Repeater) for flow capture/replay.
- `jwt_tool` for `id_token`/`access_token` inspection and tampering (`alg=none`, key confusion — see hunt-session-management for depth).
- `curl` + `jq` for discovery doc and token endpoint scripting.
- Burp extension **Autorize** / **Auth Analyzer** for automated scope/role diffing across accounts.

## Root Causes

- `redirect_uri` validated by substring/prefix match instead of exact string match against a registered allow-list.
- `state` not bound to the session, not single-use, or not validated at all on callback.
- Authorization code not bound to the `client_id`+`redirect_uri` that requested it.
- Consent screen skipped or scope not re-validated server-side against the client's registered allowed scopes.
- Implicit flow used where Authorization Code + PKCE is appropriate.

## Validation Gate (minimum proof)

- For redirect_uri bypass: screenshot/log of the IdP issuing a real `code` or `token` to a redirect_uri you do not control that is **not** the registered one, or the exact registered one reached via a path you manipulated.
- For state CSRF: a working PoC HTML page that, when opened by an authenticated victim, results in the victim's account linked to the attacker's identity — demonstrated against a second test account, never a real user.
- For scope escalation: side-by-side decoded JWT/introspection response showing a scope/claim that was never consented to.
- A captured code successfully redeemed from an origin other than the registered redirect_uri is the strongest single proof — screenshot the token response.

## Gotchas

- **Minimum proof, not plausibility.** "The regex looks loose" is not a finding — you must get a real code/token delivered to the rogue endpoint.
- **Common N/A:** redirect_uri using exact-match allow-list with no wildcard and no path traversal normalization bug — close as N/A, don't force it.
- **Overclaim trap:** an open redirect on the client app's own `/cb?next=` is not automatically "OAuth token theft" — you must prove the token/code actually transits through that redirect and is observable (check Referer policy, `Referrer-Policy: no-referrer` kills this).
- Many IdPs (Google, Microsoft, Okta) already enforce exact redirect_uri match — this skill matters most on custom/self-hosted Authorization Servers.
- `state`-less flows are sometimes intentionally safe if the app binds the session via a different anti-CSRF cookie — check before claiming CSRF.
- Don't confuse the OIDC `nonce` (replay protection for id_token) with `state` (CSRF protection) — test both independently.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **redirect_uri bypass to code theft** — Can a loosely validated redirect_uri exfiltrate the authorization code/token to an attacker domain?
2. **state parameter absence (CSRF)** — Is the state parameter missing or not validated, enabling CSRF-based account linking?
3. **Scope escalation** — Can you request or retain scopes beyond what the client application was granted?
4. **Token leakage via implicit flow/referer** — Does the access token leak via the URL fragment/Referer header to third-party resources loaded on the callback page?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Open redirect on client app → code/token leakage via Referer → full account takeover (chain with hunt-host-header if the redirect target is host-header-derived).
- state CSRF → login/account-linking CSRF → victim's real account hijacked by attacker-controlled IdP identity.
- Scope escalation → excessive data exposure once the over-scoped token hits the API — chain into hunt-api-abuse.
- Leaked authorization code → feeds into hunt-session-management if the resulting session token has its own weaknesses (predictable, non-expiring).
