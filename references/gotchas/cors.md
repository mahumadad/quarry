# Gotchas: CORS Misconfiguration

## Common False Positives
- Wildcard `Access-Control-Allow-Origin: *` on a public, unauthenticated API or static resource (public datasets, CDN assets, fonts, open documentation APIs). This is expected and intentional. Browsers do not send cookies on wildcard responses.
- Wildcard combined with `Access-Control-Allow-Credentials: true`: browsers reject this combination, so it is not exploitable as written. It is a configuration smell, not an exploit.
- Reflected Origin on an endpoint that returns no user-specific or sensitive data and requires no ambient credentials.
- Authentication carried by a bearer token in an `Authorization` header or custom header held in JavaScript memory, not by cookies. A hostile origin cannot read the token, so reflected origins do not by themselves yield cross-site data theft.
- Cookies with `SameSite=Lax` or `Strict` (browser default in modern browsers when unspecified): cross-site fetches do not include them, so credentialed CORS abuse fails even when the server reflects origins.
- `Access-Control-Allow-Origin: null` returned only to requests that sent `Origin: null` on a public resource.
- CORS headers present on error responses or OPTIONS preflight only, while the actual data response carries no permissive headers.
- Allowlisted origins that are all owned by the same organization and verified (first-party subdomains) with no takeover or XSS on them.
- Origin validated with a correct exact-match allowlist; a differing result for an unrelated origin is the control behaving properly.

## Overclaim Traps
- "Critical data theft" reported from reflected Origin alone. You need credentialed access to sensitive, user-specific data to be readable cross-origin.
- Claiming the `null` origin is exploitable without showing a realistic way to produce it (sandboxed iframe, data/file contexts) and that sensitive credentialed data is returned to it.
- Reporting subdomain trust (`*.example.com` allowed) as exploitable without a demonstrated XSS or takeover on a subdomain. State it as conditional.
- Conflating CORS with CSRF. CORS governs reading responses; it does not by itself allow state-changing requests that CSRF could already perform.
- Rating high for intranet or localhost-only APIs reached from the internet without showing reachability from a victim's browser.
- Treating missing `Vary: Origin` as a standalone finding; it matters only for caching poisoning scenarios that must be demonstrated.
- Reporting a permissive policy on an endpoint behind IP allowlisting or network-level authentication without showing a victim browser can reach it.

## Minimum Proof Required
- The specific endpoint returns sensitive, user-specific data for an authenticated session (show what data, redacted).
- The response carries `Access-Control-Allow-Origin` for an attacker-controlled origin together with `Access-Control-Allow-Credentials: true`, captured as raw headers.
- Authentication on that endpoint is ambient (cookies or HTTP auth) and the cookie attributes allow cross-site inclusion (SameSite=None; Secure, or legacy behavior). Record the Set-Cookie attributes.
- A cross-origin browser read demonstrated from a controlled origin using a test account (not just a curl header), showing the data is accessible to script on that origin.
- Control: a non-allowlisted origin is handled differently, or the same request without credentials returns no sensitive data.
- Test with accounts you own; never read other users' real data to prove impact.
- Label the claim: Demonstrated (browser cross-origin read of authenticated data), Inferred (headers prove policy but no read), Unproven (wildcard on public resource).

## When to Mark N/A
- API is intentionally public, unauthenticated and read-only, and returns only public data.
- Authentication uses non-ambient credentials (bearer tokens in headers) and no cookie auth path exists.
- No CORS headers are returned at all (same-origin policy is in effect), which is the secure default.
- Allowed origins are an exact-match allowlist of verified first-party origins with no known takeover or XSS.
- The service is not browser-consumed (machine-to-machine) and no browser can reach it.
