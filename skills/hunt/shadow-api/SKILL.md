---
name: shadow-api
description: >
  Hunt for shadow, undocumented, legacy and deprecated API surface: old versions still live
  (v1 behind v2), endpoints referenced only in client JS/mobile bundles, HTTP methods the docs
  don't expose, internal/debug routes reachable externally, and parameters the current UI dropped
  but the server still honours. These surfaces often lack the auth/validation the "official" API
  gained. Use when an app has a documented API but you suspect more exists, or after recon finds
  version prefixes, swagger/openapi fragments, or endpoint strings in JS. Keywords: shadow api,
  undocumented endpoint, api versioning, v1 v2, deprecated api, hidden endpoint, http method,
  swagger openapi, debug route, legacy parameter, zombie api.
  Do NOT use for generic content discovery of web pages (that's active-recon/web-crawling) — this
  is specifically about API endpoints/methods/params that exist but are not meant to be reachable.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-1059, CWE-285, CWE-539, CWE-16]
  mitre_attack: [T1190, T1526, T1213]
  tools: [ffuf, curl, burp, kiterunner, jsluice]
depends_on: [active-recon, api-discovery, js-analysis]
feeds_into: [chain-analysis, broken-access-control, info-disclosure]
chains_with: [idor, auth-bypass, broken-access-control]
---

## Signals

- A versioned API (`/api/v2/...`) — older `/api/v1/` (or `/v0/`, `/internal/`, `/legacy/`) often
  still responds and may predate the auth/validation hardening applied to v2.
- Endpoint strings, route tables, or feature flags embedded in client JS/SPA bundles or mobile
  app packages that the live UI never calls (chain js-analysis).
- A documented endpoint supporting only `GET`/`POST` in the UI while the server also honours
  `PUT`/`DELETE`/`PATCH`/`OPTIONS` (mass-assignment, deletion, or admin writes hiding behind a
  method the docs omit).
- Swagger/OpenAPI/GraphQL schema fragments exposed (`/swagger.json`, `/openapi.json`, `/v2/
  api-docs`, `/_schema`, introspection) listing routes the UI doesn't surface.
- Parameters the current client stopped sending but the backend still reads (`debug=1`, `admin=
  true`, `format=raw`, `include=internal`, old field names in the model).
- Hostname/subdomain patterns like `api-legacy.`, `internal-api.`, `staging-api.` reachable
  externally.

## Prerequisites

- An identified base API and at least one authenticated + one unauthenticated token (to compare
  what each version/route enforces).
- Client JS/mobile bundles pulled for endpoint extraction (chain js-analysis), and any
  swagger/openapi doc found in recon.
- A wordlist of API paths/versions/methods and a request-replay tool (Burp/`ffuf`/`kiterunner`).

## Methodology

1. **Version rollback.** Take a known v2 endpoint and walk the version down; compare auth and
   response:
   ```bash
   for v in v3 v2 v1 v0 internal legacy beta; do
     code=$(curl -s -o /tmp/sv.out -w "%{http_code}" "https://target/api/$v/users/me" \
       -H "Authorization: Bearer $TOKEN")
     echo "$v -> $code  len=$(wc -c </tmp/sv.out)"
   done
   # Also try the SAME path with NO auth on each version — an old version may skip authz.
   ```
   A v1 that returns data v2 gates (or returns without the token) is a shadow surface.

2. **Extract endpoints from client code.** Mine the bundles/mobile app for routes the UI doesn't
   exercise (chain js-analysis):
   ```bash
   # jsluice / grep for path-like strings and fetch/axios calls
   for js in $(curl -s https://target/ | grep -oE 'src="[^"]+\.js"' | sed -E 's/src="([^"]+)"/\1/'); do
     curl -s "https://target/$js" | grep -oE '"/(api|v[0-9]|internal|admin)/[A-Za-z0-9_/{}.-]+"'
   done | sort -u
   # jsluice urls -R '/api/' app.js    # if available, structured extraction
   ```
   Call each discovered route; flag ones absent from the docs/UI.

3. **HTTP method expansion.** For each known endpoint, probe methods the docs don't mention:
   ```bash
   for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do
     echo "== $m /api/v2/orders/123 =="
     curl -s -o /dev/null -w "%{http_code}\n" -X "$m" "https://target/api/v2/orders/123" \
       -H "Authorization: Bearer $TOKEN"
   done
   # OPTIONS often lists the Allow: header; a 200/204 on PUT/DELETE the UI never issues is shadow.
   ```
   `Allow:` headers and `405 Method Not Allowed` vs `200` distinguish honoured methods.

4. **Schema/doc harvesting.** Pull any machine-readable schema and diff against the live UI:
   ```bash
   for d in /swagger.json /openapi.json /v2/api-docs /api-docs /_schema /api/schema; do
     curl -s -o /tmp/doc "https://target$d" && head -c 200 /tmp/doc && echo " <= $d"
   done
   # Enumerate every path in the doc; the ones the UI never calls are shadow candidates.
   ```

5. **Legacy/zombie parameter probing.** Replay a current request adding retired/debug params and
   watch for behaviour change (verbose output, skipped checks, extra fields):
   ```bash
   curl -s "https://target/api/v2/report?id=1&debug=1&format=raw&include=internal"
   # old field names in the body: mass-assignment of fields the current client dropped
   ```

6. **Auth differential, the key test.** For every shadow surface found, compare what it enforces
   vs the official one: does v1/the alt method/the internal route skip authn, skip authz, or
   accept fields the hardened path rejects? That delta is the finding.

7. **Confirm impact, respect scope.** A reachable undocumented endpoint is only a finding when it
   grants something the official surface doesn't (unauthenticated data, cross-user access, a
   write/delete). Prove that; stop before mass-exercising destructive methods without a gate.

## Tooling

- `ffuf` — version/path/parameter fuzzing (`-w api-wordlist -u https://target/api/FUZZ/...`).
- `kiterunner` — API-route-aware content discovery (uses method+path+body wordlists, better than
  plain dir brute for APIs); verify flags with `-h` first.
- `jsluice` / grep — structured URL/endpoint extraction from JS bundles.
- Burp (Repeater for method/param expansion, Intruder for version sweeps; compare auth-on vs
  auth-off responses side by side).
- `curl` for the auth-differential and OPTIONS/Allow probing.

## Root Causes

- Old API versions kept live for backward compatibility and never retired or re-secured — v1
  predates the authn/authz/validation that v2 added.
- Endpoints shipped in client code but "hidden" by not linking them in the UI — security by
  obscurity; the route is fully reachable.
- Framework default routing exposing methods (PUT/DELETE/PATCH) the developers only intended via
  the UI's GET/POST.
- Internal/debug/admin routes bound to the same externally-reachable host without a network or
  auth boundary.
- Backends that still read parameters/fields removed from the current client (no server-side
  allowlist of accepted inputs).
- Exposed OpenAPI/Swagger/introspection advertising the whole surface, including unfinished routes.

## Validation Gate (minimum proof)

- **Demonstrated:** a shadow surface reached and shown to grant something the official API does
  not — an undocumented/legacy endpoint returning data without the auth v2 requires, a method
  (PUT/DELETE) performing a write/delete the UI never exposes, or a zombie parameter changing
  behaviour (verbose internals, skipped check, mass-assigned field). Include the request, the
  response, and the contrast with the hardened path.
- **Inferred:** an undocumented endpoint/method/param is reachable (non-404, non-405) but you
  haven't yet shown it grants more than the official surface — existence proven, differential
  impact pending.
- **Unproven:** "there's probably a v1" or "swagger lists routes" with no request actually
  reaching a surface that matters. Do not report; log as a lead.
- Classify the sub-type (legacy version / JS-hidden endpoint / extra method / zombie parameter /
  exposed schema) and the exact gap vs the official API.

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| Version rollback | `/api/v1/` , `/v0/` , `/internal/` for a known v2 path | reach an un-hardened old version |
| Auth-off replay | same path, drop `Authorization` | find versions/routes skipping authn |
| JS-mined route | endpoint string from a bundle not in UI | discover hidden routes |
| Method expansion | `PUT/DELETE/PATCH/OPTIONS` on a GET/POST route | honoured method the docs omit |
| Schema harvest | `/swagger.json` `/openapi.json` `/v2/api-docs` | enumerate full declared surface |
| Zombie param | `?debug=1&format=raw&include=internal` | trigger retired behaviour/fields |
| Mass-assign field | old field name in body | backend still binds it |

```bash
# Detection: auth-differential across versions for one known endpoint.
EP="users/me"; declare -A R
for v in v2 v1 v0 internal legacy; do
  a=$(curl -s -o /dev/null -w "%{http_code}" "https://target/api/$v/$EP" -H "Authorization: Bearer $TOKEN")
  u=$(curl -s -o /dev/null -w "%{http_code}" "https://target/api/$v/$EP")   # no auth
  echo "$v: auth=$a noauth=$u"
done
# v1 noauth=200 while v2 noauth=401 => legacy version skips authentication (shadow surface).
# Then confirm the v1 response actually returns protected data, not an empty/redirect stub.
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| v2 enforces authz | drop to v1/legacy path | old version may lack the check entirely |
| route not in UI | call the JS-mined endpoint directly | obscurity is not access control |
| GET/POST only in docs | send PUT/PATCH/DELETE | framework may route the verb regardless |
| path blocked at edge | method override `X-HTTP-Method-Override: DELETE` | proxy sees POST, app does DELETE |
| current client allowlist | resurrect retired param/field name | server still reads it |
| 404 on guessed path | harvest exact path from swagger/openapi | precise route beats brute force |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Broken access control** — Does the shadow surface skip the authz the official one enforces?
   Chain broken-access-control / authz-matrix for cross-role/tenant access.
2. **IDOR on legacy** — Old versions often lack object-level checks; test object IDs on the
   shadow endpoint (chain idor).
3. **Mass assignment** — Do resurrected fields let you set privileged attributes
   (`role`, `isAdmin`, `verified`)? Chain mass-assignment.
4. **Info disclosure** — Debug params / verbose legacy responses leaking internals, stack traces,
   PII (chain info-disclosure).
5. **Destructive methods (gate)** — A reachable `DELETE`/`PUT` may modify state; demonstrate with
   a benign/own object and get an operator gate before touching others.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Shadow v1 skipping authn/authz → **broken-access-control** / **auth-bypass** → protected data.
- JS-hidden or legacy endpoint + object IDs → **idor** (object-level access the UI hid).
- Resurrected fields on a shadow write path → **mass-assignment** (privilege escalation).
- Debug/verbose zombie params → **info-disclosure** (internals, config, stack traces).
- Extra HTTP method (`PUT`/`DELETE`) → state change / **business-logic** abuse.

## Gotchas

- **Reachable ≠ vulnerable.** An undocumented-but-authenticated-and-authorized endpoint is just
  undocumented. The finding needs a *differential*: it grants something the official surface
  doesn't. Prove the gap, don't report mere existence.
- **404 is not always "gone".** Some APIs return 404 for unauthorized routes to hide them; a 401/
  403 elsewhere, or a 200 with a different token, can reveal the route exists — probe auth states
  before concluding absence.
- **Destructive methods need a gate.** Confirming `DELETE` is honoured on *your own* test object
  is proof; mass-deleting or mutating other objects crosses a scope boundary — stop and ask.
- **Method override is proxy-dependent.** `X-HTTP-Method-Override` only works if the stack honours
  it; a `200` might be the app ignoring the header and doing the original verb — verify the
  *effect* matches the overridden method.
- **Swagger may be aspirational.** A declared route can be unimplemented (501/404); existence in
  the doc is a lead, not a finding — the request must actually reach a working, under-secured
  surface.
- **Common N/A:** all versions enforce the same authn/authz, extra methods return 405, retired
  params are ignored by a server-side allowlist — record tested-and-safe with evidence.
