# Gotchas: Cross-Site Scripting (XSS)

## Common False Positives
- Payload reflected in raw HTML source but HTML-encoded (`&lt;script&gt;`) or inside a `<textarea>`/`<title>`/comment context where it cannot execute: reflection without execution.
- Payload reflected only in a JSON response served with `Content-Type: application/json` (and `X-Content-Type-Options: nosniff`): browsers will not render it as HTML.
- Self-XSS: payload only fires in the attacker's own session and cannot be delivered to another user (no CSRF-able sink, no shared storage).
- Execution only in a tool's DOM (Burp's renderer, curl output, an API client) and not in a real browser.
- Payload fires in a sandboxed iframe with no `allow-scripts`/`allow-same-origin`, or on an isolated origin (e.g. user-content domain) with no cookies and no access to the main app.
- CSP blocks execution (no `unsafe-inline`, strict nonces) and no bypass was demonstrated: the injection exists but is not exploitable as shown.
- `alert()` popping in the browser devtools console on your own page edit rather than through the application's response.
- Stored input that is rendered only in an admin panel with a different encoding path you did not actually confirm.
- Reflected parameter in a `Location`/`Set-Cookie` header or 3xx body only: header injection or open redirect, not XSS, unless the response renders.
- Old browsers only (IE quirks, legacy XSS filters): note it, but do not claim it for modern browsers.

## Overclaim Traps
- "Account takeover" from XSS when session cookies are `HttpOnly`, tokens are not in JS-reachable storage and no state-changing action was demonstrated.
- "Critical" for reflected XSS requiring a victim to paste a payload or on a page that needs a POST with a CSRF token you cannot forge.
- Rating self-XSS above Informational/Low.
- Stored XSS rated the same regardless of audience: a field visible only to the submitter is not stored XSS against others.
- Claiming cookie theft without showing the cookie is readable by JS (check `HttpOnly`, `Secure`, `SameSite`).
- Reporting each reflected parameter on the same page/template as separate findings when one output-encoding flaw is the root cause.
- Counting missing CSP/`X-XSS-Protection` headers as XSS. They are hardening gaps.
- DOM XSS claimed from a source/sink grep in minified JS without a working execution.

## Minimum Proof Required
- Exact URL/request, injection point (parameter, header, field) and payload, plus the context in which it lands (HTML body, attribute, JS string, URL).
- Screenshot or recording from a real browser showing execution (alert/`document.domain`/DOM change), with the browser and version noted. Prefer `alert(document.domain)` to show the origin.
- For stored XSS: proof it fires for a different user/session than the one that stored it (second account).
- For impact beyond execution: demonstrate the specific action (authenticated API call from the victim's context, readable token, form submission). Use a benign marker, never harvest real user data.
- CSP header value recorded; if present, show execution despite it.
- Delivery vector documented (link, stored location, who sees it).

## When to Mark N/A
- All user input reaches the DOM through context-correct encoding or a safe framework sink (`textContent`, React default escaping) and probes confirm no breakout.
- The reflection is inert (inside `<textarea>`, comments, JSON with correct content type) and no sniffing/rendering path exists.
- Endpoint returns only non-HTML content types with `nosniff`.
- The app is an API-only service with no HTML rendering: note XSS as not applicable to the API, but flag clients that render its data if in scope.
- Feature disabled or not reachable in the tested environment: "Not tested", not "Not vulnerable".
