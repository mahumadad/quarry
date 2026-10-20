---
name: chain-auth-to-takeover
description: >
  Analyze and validate authentication-related chains that escalate to full
  account takeover: password-reset poisoning via Host header, XSS+CSRF
  combos, OAuth redirect_uri abuse, JWT manipulation + IDOR, and session
  fixation + XSS. Use when chain-analysis flags a candidate combining an
  identity-map finding (token/flow weakness) with a web-layer injection or
  logic flaw.
  Do NOT use for chains that don't terminate in attacker control of a
  victim account/session — a standalone auth bypass with no victim-
  targeting component is reported directly, not chained here.
metadata:
  type: chain
  phase: chaining
  tools: [burp, jwt_tool, curl, mitmproxy]
depends_on: [chain-analysis, identity-map]
feeds_into: [finding-validation, report-writing]
chains_with: [chain-xss-to-account-takeover, chain-idor-to-mass-data]
---

## Signals

- identity-map flagged a password-reset flow, OAuth redirect validation, JWT claim trust, or
  session-fixation-prone login flow as a candidate weakness.
- A reflected or stored XSS finding exists on a page reachable by a victim who also holds a
  session/CSRF token worth stealing.
- chain-analysis scored a pair combining any identity-map weakness with an injection/logic
  finding ≥1.

## Prerequisites

- The underlying identity weakness (reset flow, OAuth flow, JWT handling, session handling)
  already mapped by identity-map with the specific parameter/header involved.
- A second account or test identity to play the "victim" role — never test takeover chains
  against a real user's account without that user's or the client's explicit authorization
  for that specific account.

## Methodology

1. **Password reset + Host header poisoning.**
   - Confirm the reset-link generation uses the request's `Host` (or `X-Forwarded-Host`)
     header to build the link sent to the victim, rather than a server-side configured
     domain.
   - PoC: trigger a reset for a test account you control while supplying an attacker-
     controlled `Host`/`X-Forwarded-Host`, confirm the resulting email contains a link
     pointing at the attacker domain, and confirm the reset token is valid when visited
     there. This full loop (request → received email → valid token on attacker domain) is
     required for Demonstrated status — a request that merely reflects the header in a
     *response* is not sufficient evidence of the full chain.

2. **XSS + CSRF.**
   - Where a CSRF-protected action exists (state-changing, token-guarded) but the same origin
     has an XSS hole, demonstrate that the XSS can read/exfiltrate the CSRF token and replay
     it — this converts a "well-protected" action into one the stored/reflected XSS can
     still trigger on the victim's behalf.
   - Confirm the token is actually reachable from the XSS context (not `HttpOnly`-cookie-only
     tokens inaccessible to JS, and not a double-submit cookie pattern where the cookie
     itself is also inaccessible).

3. **OAuth + redirect_uri abuse.**
   - From identity-map's OAuth flow trace, confirm whether `redirect_uri` validation is exact-
     match, prefix-match, or absent.
   - PoC: register/identify an allowed-but-attacker-influenced redirect target (open redirect
     on an allowed domain, a subdomain takeover, or a path traversal within an allowed
     prefix) and confirm the authorization code/token is delivered there.
   - Confirm `state` is checked on the callback — if absent, note the CSRF-login angle as a
     separate but related sub-finding.

4. **JWT manipulation + IDOR.**
   - From identity-map's JWT claim catalogue, identify any claim (user ID, tenant ID, role)
     that is trusted by a backend resource-access check without independent authorization
     verification.
   - PoC: modify the claim (re-sign if the key/algorithm weakness allows, or use an unsigned/
     alg-none variant if accepted) and confirm access to another user's/tenant's resource
     that the modified claim implies.

5. **Session fixation + XSS.**
   - Confirm the application accepts an attacker-supplied session identifier (via URL param
     or non-`HttpOnly` cookie set before login) and does not rotate it on successful auth.
   - Combine with an XSS/open-redirect to deliver the fixed session ID to a victim, then
     confirm the attacker's pre-set session becomes authenticated once the victim logs in.

## Validation gate

- Every PoC in this skill requires a closed loop with observable victim-side evidence
  (an email received, a session that becomes authenticated, a token successfully replayed)
  — not just a request that "looks like it should work."
- Victim-side testing uses only test accounts/identities explicitly authorized for this
  purpose — never a real user without separate, explicit authorization for that account.
- Impact claims distinguish "I could have done this to any user" (demonstrated against a
  test account, generalizable) from "I did this to a real user" (never do this without
  explicit, separate authorization) — report the former unless the client has explicitly
  scoped the latter.

## Gotchas

- Host-header reset poisoning frequently fails silently (app ignores the header, uses a
  config value) — confirm the actual link content before investing further, don't assume
  from the header being reflected elsewhere on the site.
- CSRF tokens stored in `sessionStorage`/`localStorage` are XSS-reachable by design — don't
  report "CSRF protected" as a mitigating factor without checking where the token actually
  lives.
- OAuth `redirect_uri` prefix-matching bypasses often require a genuinely existing open
  redirect or subdomain takeover on the allowed domain — don't claim the chain works until
  that secondary primitive is itself confirmed, not hypothesized.
- JWT re-signing attacks (key confusion, `alg:none`) are frequently already patched in
  mainstream libraries — verify library and version before spending budget on a dead
  pattern; log it as a dead end if the library is current and config looks correct.
- Session fixation is often only exploitable on first login (not already-authenticated
  sessions) — confirm the actual vulnerable window before writing it up as broader than it is.
