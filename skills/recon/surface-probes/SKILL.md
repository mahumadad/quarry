---
name: surface-probes
description: >
  Mandatory pre-hunt surface probes — 9 concrete curl-based checks (A-I) that
  run against every live host BEFORE dispatching any hunter agent. These detect
  attack surface that passive recon and port scanning miss: hidden paths, method
  confusion, cache deception, CRLF injection, CORS bypass, HTTP/2 issues.
  Keywords: surface probe, pre-hunt, method matrix, cache deception, CRLF,
  CORS bypass, path enum, well-known, desync.
  Do NOT use as a replacement for hunt skills — these are lightweight probes
  that identify WHERE to hunt, not full exploitation.
metadata:
  type: recon
  phase: recon
  tools: [curl, httpx]
  mandatory: true
depends_on: [recon/port-scan, recon/api-discovery, web-crawling]
feeds_into: [hunt-*]
chains_with: []
---

## Signals

- Live hosts with HTTP/HTTPS services have been discovered
- About to transition from RECON/MAPPED to HUNTING phase
- This skill is MANDATORY — skipping requires explicit operator override with
  a brain entry citing why

## Prerequisites

- Live host list from active-recon or port-scan
- Scope confirmed for all targets
- At least one host responds on 80 or 443

## Methodology

Run probes A through I against EVERY P1 (priority-1) host. Each probe is pure
curl — no heavy tools, no agent dispatch. Record results in `.pentest-state/
surface-probes.json`.

### Probe A: Path Enumeration (hidden endpoints)

```bash
# Well-known paths
for path in \
  .well-known/openid-configuration \
  .well-known/oauth-authorization-server \
  .well-known/jwks.json \
  .well-known/security.txt \
  .well-known/assetlinks.json \
  .well-known/apple-app-site-association \
  robots.txt sitemap.xml \
  graphql /graphql /api/graphql \
  swagger.json /api/swagger.json openapi.json /api/docs \
  _next/data __nextjs_original-stack-frame \
  .env .git/HEAD .git/config \
  wp-json/wp/v2/users \
  actuator/health actuator/env actuator/info \
  server-status server-info \
  debug trace elmah.axd; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' "https://{host}/$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$path → $code"
done
```

Record: every non-404 path with status code and response size. Flag any
200/301/302/403 — a 403 means the path EXISTS and may be accessible via
method or header manipulation (Probe B).

### Probe B: HTTP Method Matrix

```bash
# For each interesting path from Probe A (and auth endpoints)
for method in GET POST PUT DELETE PATCH OPTIONS TRACE PROPFIND MKCOL MOVE COPY; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' -X "$method" "https://{host}/{path}")
  echo "$method → $code"
done
```

Flag: different response codes across methods (e.g., GET=403 but POST=200),
TRACE enabled (reflects headers → XST), OPTIONS reveals unexpected methods,
PROPFIND/MKCOL succeeding (WebDAV).

### Probe C: Cache Deception

```bash
# Append static extensions to authenticated endpoints
for ext in .css .js .png .svg .avif /anything.css; do
  curl -sk -D- "https://{host}/api/me${ext}" \
    -H "Cookie: {session_cookie}" | grep -i 'cache-status\|x-cache\|age:\|cf-cache'
done
# Also test path confusion
curl -sk -D- "https://{host}/static/..%2fapi/me" \
  -H "Cookie: {session_cookie}" | head -20
```

Flag: any HIT or age>0 with authenticated content — web cache deception.

### Probe D: CRLF / Response Splitting

```bash
# Test redirect parameters and any user-controllable header value
for payload in '%0d%0aX-Injected:true' '%E5%98%8A%E5%98%8DX-Injected:true' \
  '%0d%0aSet-Cookie:pwned=1'; do
  resp=$(curl -sk -D- "https://{host}/redirect?url=https://example.com${payload}" 2>&1)
  echo "$resp" | grep -i 'x-injected\|set-cookie.*pwned' && echo "CRLF DETECTED"
done
```

### Probe E: CORS Preflight Matrix

```bash
# Test multiple origin bypass patterns
for origin in \
  'null' \
  "https://evil.com" \
  "https://{host}.evil.com" \
  "https://evil-{host}" \
  "https://{host}evil.com" \
  "file://" \
  "https://subdomain.{host}"; do
  resp=$(curl -sk -D- "https://{host}/api/me" \
    -H "Origin: $origin" \
    -H "Access-Control-Request-Method: GET" 2>&1)
  acao=$(echo "$resp" | grep -i 'access-control-allow-origin')
  acac=$(echo "$resp" | grep -i 'access-control-allow-credentials.*true')
  [ -n "$acao" ] && echo "Origin: $origin → $acao $acac"
done
```

Flag: any reflected origin + credentials:true. Null origin + credentials is
exploitable. Subdomain prefix/suffix reflection is exploitable if attacker
controls any subdomain.

### Probe F: Header Injection Points

```bash
# X-Forwarded-For / Host header manipulation
curl -sk -D- "https://{host}/login" -H "X-Forwarded-Host: evil.com" | head -30
curl -sk -D- "https://{host}/login" -H "Host: evil.com" | head -30
curl -sk -D- "https://{host}/reset-password" -H "X-Forwarded-Host: evil.com" | head -30
# Check if host header is reflected in links, redirects, or password reset URLs
```

### Probe G: HTTP Version & Protocol Issues

```bash
# HTTP/2 support and potential desync
curl -sk --http2 -D- "https://{host}/" | head -5
# H2C upgrade attempt (cleartext HTTP/2 — bypasses reverse proxy rules)
curl -sk "http://{host}/" \
  -H "Upgrade: h2c" \
  -H "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA" \
  -H "Connection: Upgrade, HTTP2-Settings" -D- | head -10
```

### Probe H: Security Headers Baseline

```bash
curl -sk -D- "https://{host}/" -o /dev/null | grep -iE \
  'strict-transport|content-security-policy|x-frame-options|x-content-type|referrer-policy|permissions-policy|x-powered-by|server:'
```

Record: missing headers as INFO findings (not vulnerabilities alone).
X-Powered-By and Server values feed tech-stack-fingerprint.

### Probe I: Cookie Security Audit

```bash
# Capture Set-Cookie headers from login/auth flow
curl -sk -D- "https://{host}/api/auth/login" \
  -X POST -d '{"email":"test@test.com","password":"test"}' \
  -H "Content-Type: application/json" | grep -i 'set-cookie'
# Check: HttpOnly, Secure, SameSite, __Host- prefix, path scope
```

## Validation Gate

Surface probes don't produce findings directly — they produce TARGETS for
hunter agents. Each probe result is classified:

- **INVESTIGATE** — anomalous response that needs a hunter skill
- **NOTE** — informational, feeds into asset/coverage tracking
- **CLEAR** — expected response, no action needed

A per-class skip in hunting requires citing which surface probe cleared it.
"No surface probe evidence" is not a valid reason to skip a vuln class.

## Output

Persist to `.pentest-state/surface-probes.json`:
```json
{
  "host": "target.com",
  "probed_at": "2026-10-20T...",
  "results": {
    "A_paths": [{"path": ".well-known/openid-configuration", "code": 200, "size": 1234}],
    "B_methods": [{"path": "/admin", "GET": 403, "POST": 200}],
    "C_cache": [],
    "D_crlf": [],
    "E_cors": [{"origin": "null", "reflected": true, "credentials": true}],
    "F_headers": [],
    "G_protocol": {"http2": true, "h2c_upgrade": false},
    "H_security_headers": {"missing": ["CSP", "Permissions-Policy"]},
    "I_cookies": [{"name": "session", "httponly": true, "secure": true, "samesite": "Lax"}]
  },
  "investigate": ["E_cors: null origin reflected with credentials"],
  "notes": ["H: missing CSP", "A: GraphQL endpoint at /graphql"]
}
```

## Gotchas

- Probe A: .env/.git paths on production are INFO until content is verified —
  a 403 on .git/HEAD means git IS there but may be access-controlled
- Probe B: TRACE enabled alone is low/info — only escalates with XST (cookie
  without HttpOnly + TRACE = session theft)
- Probe C: cache deception needs authenticated content in the cached response,
  not just a cache HIT on a public page
- Probe E: CORS wildcard (*) WITHOUT credentials:true is by design and not
  exploitable for authenticated data theft
- **Rate limiting via proxy/Tor:** Tools like nuclei saturate Tor circuits
  with parallel connections → "connection refused" → 0 matches ≠ clean.
  When operating through Tor/VPN/proxy with limited bandwidth: run one host
  at a time, set `-rl 1 -c 1` (nuclei) or equivalent rate limiting, and
  accept that full-speed scanning requires a direct authorized IP.
  Surface probes (curl-based) are inherently sequential and safe over Tor;
  only parallelized tools need throttling.
