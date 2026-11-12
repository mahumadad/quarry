# Gotchas: Cross-Site Request Forgery (CSRF)

## Common False Positives
- No CSRF token, but the endpoint authenticates via `Authorization: Bearer` header, custom header or API key that browsers do not attach automatically.
- Cookie is `SameSite=Lax` or `Strict` and the action is a POST/PUT/DELETE: cross-site requests will not carry the cookie in modern browsers (except the Lax top-level navigation GET case and the short "Lax+POST" Chrome window for cookies without explicit SameSite).
- Endpoint requires `Content-Type: application/json` and enforces it with a CORS preflight that the attacker origin fails: simple forms cannot send it.
- Token is missing from your forged request but the server still rejects it for another reason (Origin/Referer check, custom header), and you did not verify acceptance.
- Request succeeds only because your replay used the victim cookie from the same browser profile with devtools, not from a cross-origin page.
- State-unchanging endpoints (logout on a harmless site, search, read-only GET): no meaningful impact.
- Login CSRF on apps where it has no consequence is Low/Informational.
- Token "not validated" claim based on removing it in Burp where the server happens to accept because the session is bound by another check (e.g. Origin).

## Overclaim Traps
- "Account takeover via CSRF" for actions that need the current password, 2FA step or re-authentication.
- Rating CSRF on non-sensitive actions (change theme, mark notification read) as High.
- Claiming exploitability in all browsers without testing; SameSite defaults differ by browser and version.
- Ignoring prerequisite user interaction and phishing as a requirement in CVSS (UI:R).
- Using a GET-based action found in logs/proxy as proof without showing a real cross-origin trigger.
- Treating missing anti-CSRF token as Critical without proving cookies are sent cross-site.
- Duplicating findings for each form when a single framework-level protection is absent.

## Minimum Proof Required
- A standalone proof-of-concept HTML page hosted on a different origin from the target (not same-origin, not localhost-to-localhost if target is remote) that triggers the state change.
- Evidence of the victim browser session: cookie attributes (`SameSite`, `HttpOnly`, `Secure`) captured from the actual `Set-Cookie` header.
- Before/after state of the affected resource under a test account.
- Browser and version used, since SameSite behaviour varies.
- Confirmation that no token, custom header, or Origin/Referer check blocked the request; include server response.
- Description of the sensitive action and why it matters (e.g. email change, fund transfer, role grant).

## When to Mark N/A
- Authentication is by non-cookie credentials only (Bearer tokens in headers, mTLS) with no ambient browser credentials.
- Valid anti-CSRF tokens are tied to the session, unpredictable, and validated on every state-changing request, and bypass attempts (token removal, reuse, method override, other user's token) failed.
- Cookies are `SameSite=Strict` (or Lax with only POST-based actions) and no same-site subdomain/XSS gadget exists to bypass.
- The application has no state-changing, authenticated functionality in scope.
