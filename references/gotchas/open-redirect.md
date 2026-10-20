# Gotchas: Open Redirect

## Common False Positives
- Redirect to a same-origin path or subpath (`/dashboard`, `/login?next=/account`): the destination stays on the same site, so there is no off-site redirection and no open redirect.
- Redirect to a relative URL after login, logout or language switch that the server normalizes to the same host.
- Redirect target restricted by an exact allowlist or by a server-side lookup (mapping an ID or key to a URL) where the user only selects among trusted values.
- Client-side navigation parameters that only change SPA routes, not the browser location to another origin.
- Redirects that require the attacker to already control the victim's session or the stored destination (account setting an admin chose). That is configuration, not an open redirect.
- Intermediate "You are leaving this site" interstitial pages that require an explicit user click and show the destination clearly. These reduce impact; consider downgrade to informational depending on policy.
- Same-organization cross-domain redirects (brand domains, regional domains) that are intentionally trusted.
- Redirect responses (3xx) to an off-site `Location` that were produced by a CDN or WAF health/geo rule and not influenced by your input.
- Parameter reflected inside page content, not in a `Location` header or navigation sink.

## Overclaim Traps
- Rating high or critical for a standalone open redirect. Without chaining, impact is usually low (phishing aid). Chain claims must be proven.
- Claiming OAuth token theft or account takeover from an open redirect without showing the OAuth server accepts a `redirect_uri` that lands on the vulnerable path. Authorization servers that enforce exact-match registered `redirect_uri` (as OAuth 2.0 Security BCP recommends) block the usual chain; wildcard or prefix matching is what makes it exploitable.
- Assuming implicit-flow or fragment token leakage without verifying the client uses that flow. Authorization code flow with PKCE substantially changes impact.
- Claiming SSRF from a redirect that only the browser follows. Server-side following of the redirect must be shown for SSRF.
- Claiming filter bypass without noting the bypass only works in one parser or browser.
- Treating `javascript:` or `data:` URL acceptance as an XSS claim without confirming execution in the target origin.
- Counting each parameter or page that reuses the same redirect helper as a separate finding without noting the shared root cause.

## Minimum Proof Required
- A request in which a parameter you control causes a 3xx `Location` header (or an application-driven navigation) pointing to an external origin you control, with the full request and response saved.
- Confirmation that the final browser location is the external origin, not just that the parameter is reflected.
- Proof that no interstitial or allowlist prevents it, using an unrelated external domain as the destination.
- Documentation of any bypass technique's limits (which parsers and browsers behave this way) without publishing a working phishing kit.
- For OAuth/SSO chain claims: the registered `redirect_uri` matching rule observed on the authorization server (exact, prefix, wildcard), plus a test using only a test client and test account showing the code or token reaches the redirect location. Do not capture real users' tokens.
- Redirect type recorded (server 3xx, meta refresh, JavaScript sink) and authentication state required.
- Label the claim: Demonstrated (external redirect observed), Inferred (parameter likely reaches a sink), Unproven (reflection only).

## When to Mark N/A
- The application never redirects based on user input, or redirects only to server-side mapped, allowlisted destinations.
- All redirect parameters are validated against an exact-match allowlist or restricted to relative same-origin paths, confirmed with multiple destination formats.
- OAuth/OIDC clients register exact `redirect_uri` values and the authorization server enforces them, so the redirect cannot be used for the chain.
- The only observed redirects are same-origin path changes.
- No redirect functionality exists (static site): mark "Not applicable - no redirect sinks found".
