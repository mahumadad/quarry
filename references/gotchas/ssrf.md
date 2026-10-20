# Gotchas: Server-Side Request Forgery (SSRF)

## Common False Positives
- The URL parameter is fetched by the client (browser, mobile app, JS) rather than the server: that is not SSRF.
- Application validates and rejects the URL but echoes it in the error message: reflection, not a request.
- DNS callback with no HTTP callback: the host resolved the name (resolver, WAF, logging pipeline, mail scanner) but the application may not have made the request. Distinguish resolver-only from server-side fetch.
- Callback source IP belongs to a third party (link-preview service, security scanner, CDN, AV gateway, your own corporate proxy) rather than the target.
- HTTP callback with only a `User-Agent` like `Mozilla` from a browser-based preview: client-side rendering, not server fetch.
- Redirect-only: the server follows a redirect to an internal host but the allowlist is checked on the final URL and blocks it; the first hop alone is not impact.
- Webhook/integration features designed to call user-supplied URLs (by product intent) with proper egress controls: expected behaviour, not a flaw, unless it reaches internal or metadata ranges.
- Response differences (timing, status) between open and closed internal ports explained by generic validation errors rather than real connections.
- `file://`, `gopher://` or `dict://` "supported" claims based on a different error message only.

## Overclaim Traps
- "Cloud takeover" from reaching 169.254.169.254 when IMDSv2 requires a token header you cannot add, or the response was blocked or empty.
- "Internal network access" from a blind DNS/HTTP ping to one host: show reach to multiple internal targets or read content.
- Rating blind SSRF as Critical without any data read, internal pivot or secondary effect. Typically Medium/Low unless chained.
- Claiming credential theft without showing credentials actually returned, and without testing them (with operator approval).
- Port-scan results from timing differences alone presented as a map of the internal network.
- Treating a fully allowlisted fetcher (only one external domain) as SSRF.
- Assuming RCE via `gopher://` to Redis/other services without proving the protocol is enabled and the service reachable.

## Minimum Proof Required
- Out-of-band evidence you control: an HTTP request received at your collaborator/listener with timestamp, source IP, headers, and a unique token tied to your request.
- Confirmation the request came from the target infrastructure (source IP/ASN, headers, internal hostname) and not a third party.
- For impact: response content from an internal or metadata resource returned to you, or a deterministic differential (status/body/timing) reproduced against known open vs closed internal targets.
- Exact injection point (parameter, header, body field, file upload, PDF/HTML renderer) and full request.
- For metadata/credential claims: show the role name or non-secret metadata first; stop before using any credential without explicit operator authorization.
- Note redirect handling, supported schemes and any filters/bypass used.

## When to Mark N/A
- No feature fetches user-influenced URLs, hostnames or files server-side (confirmed by testing every candidate: webhooks, imports, avatars, PDF generation, link previews).
- Fetching is performed client-side only.
- Egress is strictly allowlisted to fixed destinations and bypass attempts (redirects, DNS rebinding, alternate IP encodings) failed.
- The functionality is out of scope or could not be safely tested: mark "Not tested".
