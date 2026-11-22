---
name: invariant-violation
description: >
  Systematically hunt for broken assumptions: properties the system treats as guaranteed
  (immutability, exclusivity, ordering, cleanup completeness, trust boundaries) that an
  attacker can violate. This is a meta-hunting methodology — it tells you *how to find* bugs
  by identifying what the app believes is true and testing whether that belief holds under
  adversarial conditions. Use when you have mapped the app's core workflows and want a
  structured approach to finding logic bugs that don't fit a single injection class.
  Keywords: invariant violation, broken assumption, immutability, exclusivity, ownership,
  cross-component disagreement, state inconsistency, teardown completeness, trust boundary,
  trust shift, allowed but risky, threat model gap, fail open, stale state, desync, cache
  poisoning logic, session state leak.
  Do NOT use as a first skill — this requires a mapped app (recon, crawling, tech-stack done).
  Do NOT use for specific injection payloads (sqli, xss, ssti) — this skill finds the *class*
  of bug, then hands off to the dedicated skill for exploitation. The exception is when the
  violation IS the finding (e.g., a cache returning another user's data — no injection needed).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-362, CWE-367, CWE-840, CWE-841, CWE-863, CWE-636, CWE-664, CWE-706, CWE-20]
  mitre_attack: [T1190, T1211, T1499]
  tools: [burp, curl, turbo-intruder, python-asyncio, browser-devtools]
depends_on: [active-recon, web-crawling, tech-stack-fingerprint, identity-map]
feeds_into: [chain-analysis, business-logic, race-condition, auth-bypass, idor]
chains_with: [race-condition, business-logic, auth-bypass, broken-access-control, cache-poisoning, idor]
---

## Signals

- Any multi-component system where data flows across trust boundaries (frontend→backend,
  microservice→microservice, cache→origin, CDN→origin, queue→consumer).
- Workflows with state that persists across requests (shopping cart, session, multi-step form,
  OAuth flow, file upload pipeline).
- Features where one operation assumes another already happened or will not happen concurrently
  (payment after validation, role check before data access, logout clearing all tokens).
- Code or APIs originally designed for internal/trusted callers now exposed to external users
  (admin endpoints behind a WAF, internal microservice APIs reachable via SSRF, debug routes
  behind a flag that can be toggled).
- Caching layers, CDN edge logic, or any "read from X, serve from Y" architecture where X and Y
  can diverge.

## Prerequisites

- Completed recon: crawling, tech-stack fingerprint, API discovery, identity/role map.
- A baseline understanding of the app's core workflows — you need to know what the system
  *intends* before you can test what it *assumes*.
- Burp proxy capturing all traffic, so you can replay and mutate any step in a workflow.

## Methodology

The core loop: **Identify → Enumerate → Violate → Measure**.

For each workflow or component boundary, ask: *"What does this code assume is true that an
attacker might make false?"* Then test it.

### 1. Immutability assumptions

Things the system treats as unchangeable after a certain point but that an attacker can mutate:

- **Cached values vs live data.** Does the app cache a user's role/permissions/subscription tier
  and serve stale data after a role change? Downgrade a test account's role and check whether
  cached endpoints still serve the old role's data:
  ```bash
  # 1. As admin, hit an endpoint that caches the response
  curl -s https://target/api/dashboard -H "Authorization: Bearer $ADMIN_TOKEN" | jq .role
  # 2. Downgrade the account to "viewer" via settings
  # 3. Immediately re-request with the same token — does it still say "admin"?
  curl -s https://target/api/dashboard -H "Authorization: Bearer $ADMIN_TOKEN" | jq .role
  ```

- **Signed but not bound values.** JWTs, signed URLs, HMAC'd parameters — does the signature
  cover ALL fields that matter? A signed download URL with a `user_id` parameter outside the
  signed portion lets you swap the user. Cross-reference `jwt` for specific attacks.

- **Transferred ownership.** After an object is "handed off" (file upload → processing pipeline,
  message → queue consumer, payment → fulfillment), can the original owner still mutate it?
  Upload a file, start processing, then overwrite the file at the same path before processing
  completes.

- **Frontend-computed values trusted by the backend.** Price totals, discount calculations,
  permission checks done in JS — does the server revalidate? Cross-reference `business-logic`.

### 2. Cross-component disagreement

Two parts of the system hold different views of the same state:

- **Frontend vs backend validation.** The JS enforces constraints the API doesn't (or vice versa).
  Strip the frontend validation and submit directly:
  ```bash
  # Frontend restricts quantity to 1-99; does the API?
  curl -s -X POST https://target/api/cart/add \
    -H "Content-Type: application/json" -d '{"item_id":"X","qty":0}'
  curl -s -X POST https://target/api/cart/add \
    -H "Content-Type: application/json" -d '{"item_id":"X","qty":-1}'
  curl -s -X POST https://target/api/cart/add \
    -H "Content-Type: application/json" -d '{"item_id":"X","qty":999999}'
  ```

- **Microservice boundary disagreement.** Service A authorizes a request and passes a user_id to
  Service B. Service B trusts the user_id without re-checking authorization. If you can reach
  Service B directly (via SSRF, exposed internal endpoint, or API gateway misconfiguration), you
  bypass A's check entirely.

- **Cache/CDN vs origin divergence.** The CDN caches a response keyed on URL, but the origin
  varies content by a header the CDN doesn't include in the cache key. Classic web cache
  poisoning — cross-reference `cache-poisoning`. The invariant-violation framing: the CDN assumes
  "same URL = same content" but the origin disagrees.

- **Serialization/deserialization disagreement.** The client serializes data one way
  (`JSON.stringify`, URL encoding, multipart), the server deserializes it differently, and the
  difference has security meaning. Example: a field that's a string in JSON but parsed as an
  expression server-side (the EAC voting calculator pattern — `JSON.stringify` on the client,
  `eval()` on the server).

### 3. Trust boundary assumptions

Code designed for one threat model, now operating in a different one:

- **Internal APIs exposed externally.** Enumerate shadow/internal endpoints (cross-reference
  `shadow-api`) and test whether they enforce the same auth/authz as the public surface. Common
  pattern: an `/internal/` prefix or a separate port that was behind a firewall, now reachable
  via a path traversal, host-header manipulation, or simply exposed after a migration:
  ```bash
  curl -s https://target/internal/admin/users
  curl -s https://target/api/v1/admin/users   # older version without auth
  ```

- **Debug/dev features in production.** Features gated by a flag, header, or parameter that was
  meant to be unreachable in production but isn't: `?debug=true`, `X-Debug: 1`, `/graphql` with
  introspection enabled, Swagger/OpenAPI docs at `/docs`. Cross-reference `shadow-api`.

- **Client-side transform as sanitization.** The server trusts that a value arriving via the
  frontend went through the client's transform (escaping, encoding, type coercion). The attacker
  skips the client. If the server's only defense is "the client would never send this," it has no
  defense. Identify every client-side transform in the JS bundle and test what happens when you
  bypass it.

### 4. Teardown / cleanup completeness

After a state transition, is ALL related state updated?

- **Logout completeness.** After logout, check every token and session artifact:
  ```bash
  # Capture all tokens/cookies before logout
  # Perform logout
  # Test each token individually
  curl -s https://target/api/me -H "Authorization: Bearer $JWT"         # JWT still valid?
  curl -s https://target/api/me -H "Cookie: session=$SESSION_COOKIE"    # Session alive?
  curl -s https://target/api/me -H "Cookie: refresh=$REFRESH_TOKEN"     # Refresh works?
  ```
  A logout that clears the session cookie but doesn't invalidate the JWT server-side (or vice
  versa) is a teardown incompleteness — the app assumed "logout = clean slate" but it's not.

- **Role/permission revocation.** After a user is downgraded or removed, do all cached
  permissions, active sessions, and issued tokens reflect the change? Change a user's role and
  test every previously accessible endpoint with existing tokens.

- **Deleted resource references.** When an object is deleted, are all references to it cleaned
  up? A deleted user whose comments/files/sessions persist can sometimes be "revived" by
  re-creating an account with the same identifier. Cross-reference `idor` for dangling
  references to deleted objects.

- **Multi-layer state.** The app clears the top-level state but not the underlying layer: a
  saved "lower callback" that still points to the old handler (the Exim `tls_ungetc` pattern).
  In web terms: a middleware that cached the auth decision before the logout middleware ran, or
  a WebSocket connection that stays authenticated after the HTTP session expires.

### 5. Temporal / ordering assumptions

The system assumes operations happen in a certain order, but the attacker controls timing:

- **Out-of-order step execution.** In a multi-step workflow (register → verify email → set
  password → access dashboard), skip or reorder steps. Cross-reference `business-logic` for the
  specific step-skipping methodology.

- **Parallel state machine transitions.** Two state machines that share resources but assume
  sequential access. Example: a file upload "in progress" state that blocks deletion, but the
  deletion endpoint doesn't check upload status — triggering both simultaneously can leave the
  system in an inconsistent state. For the concurrent-request technique, hand off to
  `race-condition`.

- **Stale validation.** A value validated at step N is used at step N+3, but the underlying data
  changed between N and N+3. This is TOCTOU at the application logic level, not necessarily
  requiring concurrency — a user might legitimately change their email between "send verification
  link" and "click verification link," and the link now verifies the wrong email.

### 6. Allowed-but-risky patterns

API usage that is technically legal but relies on trust the caller doesn't provide:

- **Deserialization of "trusted" data.** The app deserializes user-supplied data
  (JSON, XML, YAML, pickle, Java serialization) assuming it came from a trusted source. Cross-
  reference `deserialization` and `xxe` for specific exploitation, but the invariant being
  violated is "this data is trusted."

- **Eval-family on "sanitized" input.** The server evaluates user input as code (Python `eval`,
  Node `vm.runInContext`, PHP `preg_replace /e`, Ruby `send`) under the assumption that
  client-side sanitization made it safe. Test by sending the raw (unsanitized) value directly
  to the endpoint. For blind confirmation, use the **timing oracle** pattern:
  ```bash
  # Baseline latency
  time curl -s -X POST https://target/api/calculate -d '{"expr":"1+1"}'
  # Timing probe: if eval'd, adds N seconds of server-side delay
  time curl -s -X POST https://target/api/calculate -d '{"expr":"__import__(\"time\").sleep(3)"}'
  # Statistical validation: multiple intervals, check R² linearity
  for delay in 1 2 3 5; do
    time curl -s -X POST https://target/api/calculate \
      -d "{\"expr\":\"__import__(\\\"time\\\").sleep($delay)\"}"
  done
  ```
  A single slow response is weak evidence (network jitter, backend queue). Multiple delay
  intervals with a linear relationship between requested and observed delay (R² ≈ 1.0) is
  strong. Repeat the series to confirm determinism.

- **User-controlled format strings.** Template engines, logging frameworks, or string formatting
  that interpolate user input. Cross-reference `ssti` and `log-injection`.

## Payloads & Detection Patterns

This skill's "payloads" are structured *tests of assumptions*, not injection strings. Each test
has a hypothesis ("the app assumes X"), a manipulation ("make X false"), and a measurement
("observe whether the app behaves differently").

| Invariant class | Test shape | What to measure |
|---|---|---|
| Immutability (cached role) | Change role, replay old token/session | Response still serves old role's data |
| Immutability (signed value) | Modify unsigned portion of a signed token/URL | Server accepts the modified value |
| Cross-component (frontend/backend) | Strip client validation, submit raw value | Server accepts what client would reject |
| Cross-component (cache/origin) | Poison cache key with unkeyed header | Other users receive poisoned response |
| Cross-component (serialize/deserialize) | Send value that serializes innocuously but deserializes dangerously | Server-side code execution or type confusion |
| Trust boundary (internal→external) | Access internal endpoint from external context | No auth/authz check on the internal path |
| Teardown (logout) | Reuse every token type after logout | Any token still grants access |
| Teardown (role revocation) | Access endpoints after role downgrade | Cached permissions still active |
| Temporal (stale validation) | Change validated value between validation and use | System acts on the outdated validation |
| Temporal (out-of-order) | Skip or reorder steps in a multi-step flow | System accepts the incomplete/reordered sequence |
| Allowed-but-risky (eval) | Send code where data is expected | Server-side execution (confirmed via timing oracle) |
| Allowed-but-risky (deser) | Send crafted serialized payload | Object instantiation, RCE, or type confusion |

Surface signals that hint at invariant-violation opportunities:
- **Caching headers** (`Cache-Control`, `Vary`, `X-Cache`, `Age`) — cache/origin disagreement.
- **Multiple auth mechanisms** (cookie + JWT + API key) — teardown may miss one.
- **Versioned APIs** (`/v1/`, `/v2/`) — older version may lack newer validation.
- **Client-side heavy-lifting** (SPA with complex JS logic) — frontend/backend disagreement.
- **Background processing** (file upload → async pipeline, payment → webhook) — transferred
  ownership may not be exclusive.

## Bypass Techniques

| Defense the app relies on | Violation technique | Notes |
|---|---|---|
| Client-side validation (JS) | Direct API call bypassing the frontend | Server must revalidate independently |
| WAF/CDN rules | Access origin directly (cross-ref `waf-fingerprint` step 8) | WAF is out of the path if origin is exposed |
| Role check in middleware | Find an endpoint that skips the middleware (direct route, old version) | Not all routes go through the same middleware stack |
| Cache TTL ("it'll expire") | Poison before TTL and serve to other users | A short TTL is not a security control |
| "Internal only" network ACL | SSRF, path traversal, host-header tricks | Network controls are not application controls |
| Logout clears session cookie | JWT, refresh token, API key, WebSocket conn survive logout | Multi-mechanism auth requires multi-mechanism teardown |
| Signed/HMAC'd parameter | Modify field outside the signature scope | Signature only covers what it covers |
| Rate limiting on the endpoint | Same logic via a different endpoint or API version | Rate limit scoped too narrowly |

## Root Causes

- **Assumption creep.** The system was designed with one threat model (trusted internal users,
  hardware-enforced boundaries, single-tenant) and later exposed to a broader one (public API,
  multi-tenant, CDN-fronted) without updating assumptions.
- **Partial enforcement.** A security property (auth, immutability, cleanup) is enforced at one
  layer but not at all layers that need it.
- **Cache-origin semantic gap.** The cache keys on a subset of the request; the origin varies on
  a superset.
- **Teardown depth.** The teardown path clears the most visible state artifact but misses
  secondary or cross-system state.
- **Implicit trust in data provenance.** Data that "came from us" (another microservice, the
  client's JS, a queue) is treated as trustworthy without re-validation.

## Validation Gate (minimum proof)

- **Demonstrated:** a concrete request/response showing the invariant violated — the stale token
  granting access, the cache serving poisoned content, the internal endpoint responding without
  auth, the eval'd expression executing. Reproducible steps, not theory.
- **Inferred:** the assumption gap is confirmed (e.g., the internal endpoint exists and responds,
  the cache key doesn't include the varying header) but exploitation depends on conditions you
  couldn't create in the test environment (e.g., SSRF to reach the internal endpoint, another
  user to receive the poisoned cache). State explicitly what's missing.
- **Unproven:** "this pattern looks risky" without evidence. Record it as a hypothesis, not a
  finding.

## Gotchas

- **This is a methodology, not a vuln class.** The finding you report is the specific violation
  (IDOR, auth bypass, cache poisoning, stale session, etc.), not "invariant violation" as a
  category. This skill finds the bug; you report it under its CWE.
- **Not every assumption is security-relevant.** A cache serving stale data for a public,
  non-personalized page is a performance issue, not a vulnerability. The invariant violation
  must have a security impact to be a finding.
- **Don't conflate "the app trusts the client" with a finding.** EVERY web app sends data to the
  client and receives it back. The finding is when the server RELIES on the client for a security
  property (validation, sanitization, authorization) instead of re-checking server-side.
- **Teardown testing can lock you out.** If you're testing whether logout invalidates tokens and
  it does, your session is now dead. Use a secondary session or be prepared to re-authenticate.
- **The timing oracle requires statistics, not vibes.** A single slow response proves nothing
  (network, backend queue, GC pause). Multiple controlled delays with a consistent linear
  relationship is evidence. Two data points are not a trend — use 4+ intervals.

## Chain Anchors

Before declaring a finding from this skill complete, probe these escalation paths:

1. **Scope of the violation** — Does the broken invariant affect only the attacker's own session,
   or can it impact other users? (Cache poisoning → other users. Stale session → only the
   attacker's old session.)
2. **Persistence** — Is the violation transient (single request) or persistent (cached, stored,
   survives restart)?
3. **Cross-chain** — Can the violation be used as a stepping stone? (Stale admin token →
   `idor` → mass data export. Cache poisoning → `xss` → account takeover.)
4. **Blast radius** — How many users/tenants are affected? A per-user cache vs a shared cache
   changes severity dramatically.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Invariant violation (stale cached role) → **broken-access-control** escalation (viewer
  accessing admin data).
- Invariant violation (teardown incomplete) → **auth-bypass** (session persists after logout) →
  **idor** (access another user's data with the lingering session).
- Invariant violation (trust boundary) → **ssrf** to reach internal endpoint → **rce** via
  unprotected admin function.
- Invariant violation (cache/origin disagreement) → **cache-poisoning** → **xss** via cached
  malicious response.
- Invariant violation (serialization disagreement) → **rce** via eval/deserialization of
  untrusted data.
- Invariant violation (frontend/backend) → **business-logic** (negative quantity, price
  manipulation) → financial impact.
