---
name: idor
description: >
  Hunt for Insecure Direct Object References: horizontal (access peer users' data),
  vertical (access higher-privilege data/actions), and parameter manipulation (IDs,
  UUIDs, sequential keys). Use when any endpoint accepts an object identifier —
  order IDs, user IDs, document IDs, invoice numbers, file paths, API resource IDs.
  Keywords: idor, broken object level authorization, BOLA, horizontal privilege escalation,
  vertical privilege escalation, sequential ID enumeration, UUID guessing, forced browsing
  by ID, mass assignment via ID.
  Do NOT use for session/token forgery — use auth-bypass. Do NOT use for missing
  CSRF protection on state-changing IDOR-adjacent endpoints — note that separately via
  csrf if the IDOR also lacks a token.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-639, CWE-284]
  mitre_attack: [T1078]
  tools: [burp, ffuf, curl, autorize]
depends_on: [active-recon, web-crawling, identity-map]
feeds_into: [chain-analysis, pii-exfil]
chains_with: [auth-bypass, info-disclosure, csrf]
---

## Signals

- Any URL/body/header param holding an object reference: `/api/orders/1042`,
  `?user_id=55`, `/documents/{uuid}/download`, `account_number`, `invoice_id`.
- Sequential or low-entropy IDs (integers, incrementing, short alphanumeric) — easy to enumerate.
  Even UUIDs aren't automatically safe if the authorization check is simply missing.
- Multi-tenant SaaS apps: tenant/org ID in the path or body that isn't cross-checked against the
  authenticated user's tenant.
- Mobile app APIs / GraphQL / REST APIs that skip the web UI's client-side guards — the
  authorization logic that matters is server-side; client hiding a button is not a control.
- Endpoints that accept an ID in the *body* for an action scoped to "the current user" (e.g.
  `PUT /api/profile` with a hidden `user_id` field) — classic mass-assignment-flavored IDOR.
- Admin/staff endpoints reachable by a lower-privileged role simply by hitting the URL directly
  (vertical IDOR / forced browsing).

## Prerequisites

- **Two distinct low-privilege test accounts** (A and B) at minimum, ideally also one
  higher-privilege account, all explicitly provisioned for this engagement.
- A map of endpoints that take object identifiers (from crawling/API spec/HAR capture).
- Valid IDs owned by account A and account B respectively, captured from their own normal usage.

## Methodology

1. **Baseline both accounts' legitimate access.** As user A, capture their own resource requests
   (ID, auth token/cookie). As user B, do the same. Note each one's own valid object IDs.
   ```bash
   curl -s -b cookieA.txt https://target/api/orders/1042   # A's own order -> 200 as expected
   curl -s -b cookieB.txt https://target/api/orders/1098   # B's own order -> 200 as expected
   ```

2. **Horizontal test — swap IDs across sessions.** Use A's session/token against B's object ID
   (and vice versa):
   ```bash
   curl -s -b cookieA.txt https://target/api/orders/1098   # A's session, B's order ID
   curl -s -b cookieB.txt https://target/api/orders/1042   # B's session, A's order ID
   ```
   A `200` returning B's actual data (not a 403/404) under A's session = confirmed horizontal
   IDOR. Diff the response body against the legitimate baseline to prove it's real data, not a
   generic placeholder.

3. **Vertical test — low-priv session against admin/staff endpoints.**
   ```bash
   curl -s -b cookieA.txt https://target/api/admin/users
   curl -s -b cookieA.txt https://target/admin/export?format=csv
   curl -s -b cookieA.txt -X DELETE https://target/api/users/999
   ```
   Also test HTTP method switching (an endpoint might block GET as non-admin but allow POST/PUT
   through a less-guarded code path) and path variations (`/admin/` vs `/Admin/` vs
   `/api/v1/admin/` vs trailing slash).

4. **Mass-assignment-flavored IDOR** — check if a body param can change ownership/target:
   ```bash
   curl -s -b cookieA.txt -X PUT https://target/api/profile \
     -H "Content-Type: application/json" \
     -d '{"user_id": 999, "email": "attacker@evil.test"}'
   # then verify user 999's record actually changed, as A
   curl -s -b cookieAdmin.txt https://target/api/profile/999
   ```

5. **Enumeration at scale once one bypass is confirmed.** Sweep the ID space to size the blast
   radius (how many records are exposed) — throttle to stay within engagement rate limits:
   ```bash
   for id in $(seq 1000 1100); do
     code=$(curl -s -o /dev/null -w "%{http_code}" -b cookieA.txt "https://target/api/orders/$id")
     echo "$id: $code"
     sleep 0.2
   done | grep -v ": 403\|: 404"
   ```
   Or with ffuf against a confirmed-vulnerable endpoint:
   ```bash
   ffuf -w <(seq 1000 2000) -u "https://target/api/orders/FUZZ" \
     -b "session=$COOKIE_A" -mc 200 -t 5 -p 0.2 -o idor_sweep.json -of json
   ```

6. **UUID/opaque-ID case** — even if IDs aren't guessable, check whether *any* valid-looking ID
   from a different tenant (harvested from your own two test accounts, or leaked elsewhere in
   the app — error messages, exports, other users' shared links) bypasses authz. If IDs are
   simply unguessable with no other leak vector, note this as mitigating (not exploitable via
   enumeration) even if the authz check is still technically missing — the actual finding becomes
   "missing authz check, mitigated by unguessable ID" vs. full IDOR, and should be labeled
   accordingly rather than conflated.

7. **Automate diffing with Burp Autorize** for broad coverage once you understand the endpoint map
   — replay every request captured for the higher-priv user under the lower-priv session and flag
   response-size/status matches.

## Tooling

- `curl` with per-account cookie jars — the core manual technique; IDOR proof is fundamentally
  "request A, authenticate as B, compare."
- Burp Suite + **Autorize** extension — automates the two-session replay-and-diff workflow.
- `ffuf` — ID-space enumeration once a bypass is confirmed, to measure scope.
- Postman/HAR diffing for API-heavy targets with many object types.

## Root Causes

- Authorization check missing entirely at the data-access layer: the query fetches `WHERE id = ?`
  without also filtering `AND owner_id = session.user_id`.
- Authorization check present on the *UI* (hide the button/link) but absent on the underlying
  API endpoint.
- Trusting a client-supplied ID in the request body over the server-derived identity from the
  session/token for "my own resource" operations.
- Shared/generic middleware checks "is authenticated" but not "is authorized for *this* object."

## Validation Gate (minimum proof)

- Request sent under User A's authenticated session, targeting an object ID known (from direct
  observation) to belong to User B, returns User B's genuine data/action success — with both the
  request and response captured.
- For vertical IDOR: low-privilege session performs a privileged action/read and the server
  confirms it executed (data returned, record changed verified via a follow-up privileged-account
  check, or state-change observed), not just a 200 status with an empty/error body.
- Scope/blast-radius note: how many other objects are likely exposed (from ID space sweep), even
  if you don't enumerate all of them.

## Gotchas

- **Minimum proof, not a full data dump.** Confirm the bypass with one or two cross-account
  objects; do not loop through the entire ID space exfiltrating all records — that crosses into
  PII bulk collection and needs an explicit operator gate.
- **Common N/A:** a `403`/`404` returned for the cross-account request is *not* a vulnerability —
  that's the control working. Don't report "IDOR present" because an endpoint merely *exists* and
  *accepts* an ID; the authz check must actually fail.
- **Common N/A:** app uses per-object unguessable signed tokens (e.g., presigned URLs with HMAC)
  instead of raw sequential IDs — verify whether the token itself is bound to the resource+user
  or just the resource (still IDOR if any valid token for any object works regardless of
  requester identity).
- **Overclaim trap:** a `200` status with a generic/empty JSON shape (`{}`, `null`, default
  object) is not proof — always diff against the real data you know User B owns.
- **Overclaim trap:** testing only with your own single account and guessing IDs is not IDOR proof
  without a second account's known-good ID to confirm cross-ownership — you need both to rule out
  "that ID just doesn't exist."
- GraphQL and batch/bulk endpoints often have separate authz logic per resolver — test each field/
  mutation independently; a protected REST endpoint doesn't guarantee the equivalent GraphQL field
  is protected too.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Horizontal access** — Can you access OTHER users' data, not just confirm your own second test account's data is visible to itself?
2. **Write/delete impact** — Can you modify or delete other users' resources through the same parameter, not just read them?
3. **Pattern consistency** — Is the IDOR pattern consistent across all similar endpoints (list, detail, export, delete), or only the one tested?
4. **ID enumerability** — Can you enumerate all valid IDs? Sequential integers are trivially enumerable; UUIDs need a separate leak path.
5. **Rate limiting on exfiltration** — Does rate limiting or anomaly detection prevent mass exfiltration via the IDOR, or can thousands of records be pulled unthrottled?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- IDOR → **pii-exfil** when object data includes PII (feeds reporting/legal severity escalation).
- IDOR + predictable password-reset token in URL → **auth-bypass** (account takeover via
  IDOR-readable reset link).
- Vertical IDOR on admin action endpoints → full **auth-bypass** of the privilege model.
- IDOR exposing another user's session/API token → chains into further impersonation across the
  whole API surface — escalate to `chain-analysis` immediately given the severity.
