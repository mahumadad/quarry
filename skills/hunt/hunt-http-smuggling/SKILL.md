---
name: hunt-http-smuggling
description: >
  Hunt for HTTP request smuggling via Content-Length/Transfer-Encoding
  parsing discrepancies between front-end proxy and back-end server
  (CL.TE, TE.CL, TE.TE obfuscation), and HTTP/2-to-HTTP/1 downgrade
  smuggling (H2.CL, H2.TE). Use when the target is behind a reverse
  proxy/load balancer/CDN in front of an origin server. Keywords: request
  smuggling, CL.TE, TE.CL, TE.TE, chunked encoding, HTTP/2 downgrade,
  desync.
  Do NOT use for cache poisoning that doesn't involve a parsing desync —
  use hunt-cache-poisoning. Do NOT use for simple header injection — use
  hunt-crlf-injection.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-444]
  mitre_attack: [T1557, T1190]
  tools: [burpsuite, "HTTP Request Smuggler", curl, nc, h2csmuggler]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-cache-poisoning, hunt-session-management, hunt-host-header]
---

## Signals

- `Via`, `X-Cache`, `Server` headers indicating a reverse proxy/CDN (nginx, HAProxy, Varnish, Cloudflare, AWS ALB) in front of a different origin server (Apache, Tomcat, gunicorn, Node).
- Mixed HTTP/1.1 and HTTP/2 support advertised (`Alt-Svc`, ALPN h2).
- Any load-balanced architecture with connection reuse/keep-alive between proxy and origin (most are, by default).
- Inconsistent behavior on malformed requests between first and subsequent responses on the same connection.

## Prerequisites

- Raw socket control — Burp Repeater with **"Update Content-Length" unchecked** and raw tab, or `nc`/custom Python socket script. `curl` alone cannot craft the conflicting headers needed (it normalizes them).
- Ability to send requests with **both** `Content-Length` and `Transfer-Encoding: chunked` set simultaneously with inconsistent/obfuscated values.
- A second, unauthenticated "victim" probe request to detect smuggling via response queue desync (timing or content confusion), without needing a real victim.

## Methodology

1. **Timing-based detection (safe, confirms a desync exists before weaponizing).** Use Burp Suite's **HTTP Request Smuggler** extension to run its standard detection suite against the target, which sends TE.CL/CL.TE probes and measures response timing. Start there before hand-crafting raw sockets.

2. **CL.TE manual probe.** Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`. Send a request where the declared `Content-Length` is shorter than the body, with a smuggled request stashed after the "false" end — the back-end, following `Transfer-Encoding`, treats the extra bytes as the start of the next request on the same connection:
   ```
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 13
   Transfer-Encoding: chunked

   0

   SMUGGLED
   ```
   Send via raw socket to control exact bytes (Burp Repeater raw tab, or):
   ```bash
   printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | \
     openssl s_client -connect target.com:443 -quiet -ign_eof
   ```

3. **TE.CL manual probe.** Front-end honors `Transfer-Encoding`, back-end honors `Content-Length`. Craft a chunked body whose declared `Content-Length` only covers part of it, leaving a smuggled request as "leftover body" that the back-end reattaches to the next request on the connection:
   ```
   POST / HTTP/1.1
   Host: target.com
   Content-Length: 4
   Transfer-Encoding: chunked

   5c
   GPOST / HTTP/1.1
   Content-Type: application/x-www-form-urlencoded
   Content-Length: 15

   x=1
   0

   ```

4. **TE.TE (obfuscation).** Both front-end and back-end nominally support `Transfer-Encoding`, but one of them can be tricked into *ignoring* it via header obfuscation, downgrading the request to CL.TE or TE.CL behavior from only one side. Try each against the target and watch for a desync:
   ```
   Transfer-Encoding: chunked
   Transfer-Encoding: xchunked

   Transfer-Encoding : chunked      (space before colon)

   Transfer-Encoding: chunked
   Transfer-Encoding: identity

   X: X
   Transfer-Encoding: chunked

   Transfer-Encoding:[tab]chunked

   Transfer-Encoding: chunked, identity
   ```
   Pair each variant with a CL.TE-style body and a TE.CL-style body separately to see which interpretation wins at which hop.

5. **H2.CL / H2.TE downgrade smuggling.** If the front-end speaks HTTP/2 to clients but downgrades to HTTP/1.1 to the origin, `Content-Length` mismatches against the HTTP/2 framed body length (HTTP/2 has no `Transfer-Encoding`) can desync the downgrade:
   ```bash
   # use h2csmuggler or Burp's HTTP/2 support in Repeater to set Content-Length
   # independently from the actual :path/body length over h2
   h2csmuggler.py -x https://target.com --test
   ```

6. **Confirm impact via response queue poisoning.** Send the smuggling probe request immediately followed by a normal, distinguishable request (e.g. requesting `/robots.txt`) on the **same connection**. If the normal request's response instead contains data belonging to the smuggled request (or an entirely different client's request lands misrouted on your connection in a race), that's a working confirmation:
   ```bash
   # Burp Repeater: send group in sequence on a single connection, inspect
   # response boundaries for the "robots.txt" request receiving unexpected content
   ```

7. **Escalate only within scope/gate:** capturing another real user's request (classic smuggling impact: session hijacking) requires sending many requests in a race window against shared infrastructure — this is destructive/impactful to other users. Treat as a human-gated action; demonstrate with your own second test connection/account first (self-poisoning PoC) before any multi-victim attempt.

## Tooling

- Burp Suite extension **HTTP Request Smuggler** (automated CL.TE/TE.CL/TE.TE detection + exploit generation).
- Burp Repeater raw request tab with "Update Content-Length" disabled — mandatory for hand-crafted desync payloads.
- `h2csmuggler` for HTTP/2 downgrade testing.
- Raw `openssl s_client` / `nc` for scripted socket-level control when Burp isn't available.

## Root Causes

- Front-end and back-end servers (or library versions) disagree on how to parse a request carrying both `Content-Length` and `Transfer-Encoding`, violating RFC 7230's precedence rule (Transfer-Encoding should always win, but many implementations get this wrong or allow header obfuscation to flip it).
- Connection reuse (keep-alive) between proxy and origin without per-request boundary re-validation.
- HTTP/2-to-HTTP/1.1 downgrade that maps h2 pseudo-headers/framing to h1 headers without strict length validation.

## Validation Gate (minimum proof)

- Raw request/response capture (exact bytes, not curl's normalized form) of the smuggling payload AND the follow-up probe request whose response was contaminated/misrouted — this pairing is the proof, a single odd response is not.
- Timing-based detection results alone (Burp's automated suite) are **Inferred**, not **Demonstrated** — escalate to a content-confirmation PoC before claiming Demonstrated per project anti-fabrication rules.
- Note exact front-end/back-end server identification (`Server` header, error page fingerprints) to explain the mechanism in the report.

## Gotchas

- **Minimum proof:** a timing anomaly is a lead, not a finding — you need the second request's response to visibly contain smuggled content or be misrouted.
- **Common N/A:** HTTP/1.0-only back-ends, or infrastructure that normalizes/strips duplicate `Transfer-Encoding`/`Content-Length` at the very first hop (many modern CDNs patched this) — confirm via the timing probe before investing in raw-socket crafting.
- **Overclaim trap:** do not claim "session hijacking of other users" unless you actually captured another connection's data in your own test window — describe it as a theoretical impact class otherwise, labeled Unproven.
- `curl` cannot send genuinely conflicting `Content-Length`/`Transfer-Encoding` headers — it will silently "fix" your request. Any smuggling test attempted purely with curl that "shows nothing" is inconclusive, not a clean negative.
- Respect the project's 120s/3-retry budget — raw socket desync testing can hang connections; set explicit timeouts on `nc`/`openssl s_client`.
- This is inherently a shared-infrastructure risk — confirm scope explicitly covers the proxy/load balancer layer, not just the application, before probing.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Request queue poisoning** — Can the smuggled request poison the next legitimate user's request/response pairing?
2. **Auth/ACL bypass** — Can smuggling bypass a front-end security control (WAF, auth proxy) that the back-end alone wouldn't allow?
3. **Cache poisoning chain** — Can the smuggled payload end up cached and served to other users?
4. **Response capture for data theft** — Can smuggling be used to capture another user's response (session tokens, PII) in yours?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Smuggled request reflected into another user's response → session token theft, chain with hunt-session-management.
- Smuggling used to poison a shared cache entry → chain with hunt-cache-poisoning (same desync, different payoff).
- Smuggled request bypassing front-end auth/WAF checks (front-end sees one request, back-end processes two) → chain into hunt-broken-access-control for endpoints normally blocked at the edge.
- Host header manipulation via the smuggled request → chain with hunt-host-header.
