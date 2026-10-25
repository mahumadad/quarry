---
name: http-headers-security
description: >
  Audit HTTP security headers on every in-scope web endpoint. Covers CSP,
  HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP, COEP, CORP, Cache-Control (sensitive pages),
  and deprecated/redundant headers (X-XSS-Protection). Run after tech
  fingerprinting and before hunt-xss/hunt-clickjacking — missing headers
  widen the attack surface for those vulns.
metadata:
  type: core
  phase: scoped
  cwe: [CWE-693, CWE-1021, CWE-614, CWE-524]
  tools: [curl, httpx, nuclei, securityheaders.com]
depends_on: [tech-fingerprint, active-recon]
feeds_into: [hunt-xss, hunt-clickjacking, hunt-csrf, report-writing]
---

## Signals

- Any web endpoint in scope (HTML pages, API endpoints, login/logout flows).
- After identifying the tech stack — some headers are framework-specific.
- When building the attack surface for XSS, clickjacking, or CSRF.

## Prerequisites

- List of in-scope URLs (at least: homepage, login, authenticated page, API base).
- Tech stack fingerprint (framework defaults differ).

## Methodology

### 1. Collect headers from key pages

```bash
# Grab headers from multiple representative pages
for url in "$TARGET" "$TARGET/login" "$TARGET/api/v1" "$TARGET/dashboard"; do
  echo "=== $url ==="
  curl -sI -o /dev/null -D - "$url" 2>/dev/null | grep -iE "^(strict|content-sec|x-frame|x-content|referrer|permissions|cross-origin|cache-control|x-xss|set-cookie|server|x-powered)"
  echo
done
```

### 2. Check each header

#### Content-Security-Policy (CSP)
```bash
curl -sI "$TARGET" | grep -i "content-security-policy"
```
- Missing entirely → Medium (enables XSS exploitation)
- `unsafe-inline` in script-src → weakens CSP significantly
- `unsafe-eval` in script-src → allows eval-based XSS
- `*` or overly broad domains in script-src → 3rd party injection
- No `frame-ancestors` → clickjacking (if X-Frame-Options also absent)
- `report-uri` / `report-to` present → note for evasion awareness

#### Strict-Transport-Security (HSTS)
```bash
curl -sI "https://$TARGET" | grep -i "strict-transport-security"
```
- Missing → Medium (SSL stripping possible)
- `max-age` < 31536000 (1 year) → Low (short HSTS window)
- No `includeSubDomains` → subdomains vulnerable to stripping
- No `preload` → not in browser preload list (informational)
- Present on HTTP (not HTTPS) → misconfiguration, browser ignores it

#### X-Frame-Options
```bash
curl -sI "$TARGET" | grep -i "x-frame-options"
```
- Missing (and no CSP frame-ancestors) → Medium (clickjacking)
- `ALLOW-FROM` → deprecated, not supported by modern browsers
- `SAMEORIGIN` or `DENY` → correct

#### X-Content-Type-Options
```bash
curl -sI "$TARGET" | grep -i "x-content-type-options"
```
- Missing → Low (MIME-sniffing attacks)
- Expected: `nosniff`

#### Referrer-Policy
```bash
curl -sI "$TARGET" | grep -i "referrer-policy"
```
- Missing → Low (tokens/sensitive paths leaked in Referer header)
- `unsafe-url` or `no-referrer-when-downgrade` → leaks full URL
- `strict-origin-when-cross-origin` or `no-referrer` → correct

#### Permissions-Policy (formerly Feature-Policy)
```bash
curl -sI "$TARGET" | grep -iE "permissions-policy|feature-policy"
```
- Missing → Informational (browser features unrestricted)
- Check: camera, microphone, geolocation, payment, usb

#### Cross-Origin headers (COOP/COEP/CORP)
```bash
curl -sI "$TARGET" | grep -i "cross-origin"
```
- `Cross-Origin-Opener-Policy` → protects against Spectre-like leaks
- `Cross-Origin-Embedder-Policy` → required for SharedArrayBuffer
- `Cross-Origin-Resource-Policy` → prevents cross-origin reads

#### Cache-Control on sensitive pages
```bash
curl -sI "$TARGET/dashboard" | grep -i "cache-control"
curl -sI "$TARGET/api/v1/user/profile" | grep -i "cache-control"
```
- Sensitive pages without `no-store` → Medium (cached credentials/PII)
- API responses with PII without `private, no-store` → Medium

#### Set-Cookie flags
```bash
curl -sI "$TARGET/login" -X POST -d "user=test&pass=test" | grep -i "set-cookie"
```
- Missing `Secure` flag → cookie sent over HTTP
- Missing `HttpOnly` flag → cookie accessible to JS (XSS → session theft)
- Missing `SameSite` → CSRF vector (unless CSRF tokens used)
- `SameSite=None` without `Secure` → browser rejects it

#### Information leakage headers
```bash
curl -sI "$TARGET" | grep -iE "^(server|x-powered-by|x-aspnet|x-generator)"
```
- `Server: Apache/2.4.51` → version disclosure
- `X-Powered-By: PHP/8.1.2` → version disclosure
- Remove or genericize in production

### 3. Batch check with httpx (fast)
```bash
echo "$TARGET" | httpx -silent -status-code -title \
  -H "Strict-Transport-Security" \
  -H "Content-Security-Policy" \
  -H "X-Frame-Options" \
  -H "X-Content-Type-Options" \
  -json -o headers-audit.json
```

### 4. Automated check with securityheaders.com
```bash
# Quick reference — compare against manual findings
curl -s "https://securityheaders.com/?q=$TARGET&followRedirects=on" \
  | grep -oP 'class="[A-F](-\w+)?"' | head -1
```

### 5. Nuclei scan for header misconfigurations
```bash
nuclei -u "$TARGET" -t http/misconfiguration/ \
  -t http/exposed-panels/ \
  -tags header,security-headers,misconfig \
  -json -o nuclei-headers.json
```

## Severity Mapping

| Missing/Misconfigured | Severity | Condition |
|---|---|---|
| CSP missing entirely | Medium | Especially if XSS found |
| CSP with unsafe-inline + unsafe-eval | Low-Medium | Weakens but not absent |
| HSTS missing | Medium | HTTPS available but no HSTS |
| X-Frame-Options + CSP frame-ancestors both missing | Medium | Clickjacking possible |
| X-Content-Type-Options missing | Low | |
| Set-Cookie without Secure/HttpOnly | Medium | On session cookies |
| Set-Cookie SameSite=None | Low-Medium | Without CSRF tokens |
| Cache-Control missing on sensitive pages | Medium | Pages with PII/auth |
| Referrer-Policy missing/unsafe | Low | |
| Permissions-Policy missing | Informational | |
| Server/X-Powered-By version disclosure | Informational | |
| COOP/COEP/CORP missing | Informational | Unless Spectre-class concern |

## Validation Gate

- [ ] Headers collected from at least: homepage, login, one authenticated page, one API endpoint.
- [ ] Each header checked individually — not just a single automated scan grade.
- [ ] Missing headers that enable other attacks (CSP → XSS, X-Frame-Options → clickjacking) cross-referenced with those hunt skills.
- [ ] Set-Cookie flags checked on actual session cookies, not just any cookie.
- [ ] Cache-Control checked specifically on pages containing PII or auth tokens.

## Gotchas

- A grade from securityheaders.com is not a finding — it's a starting point. Report specific missing headers with specific impact.
- CSP `report-only` mode does not actually block anything — it's monitoring only.
- `X-XSS-Protection` is deprecated and can actually introduce vulnerabilities in some browsers (filter-based XSS). Don't recommend enabling it; if present, note as informational.
- Some frameworks set headers by default (Django's SecurityMiddleware, Rails' default_headers) — check if they're being overridden or stripped by a reverse proxy.
- API-only endpoints may legitimately skip some headers (X-Frame-Options irrelevant for JSON APIs).
- CDN/reverse proxy (Cloudflare, nginx) may add or strip headers — test against the origin if possible.
