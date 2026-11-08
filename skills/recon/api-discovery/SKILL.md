---
name: api-discovery
description: >
  Discover and map API surface: Swagger/OpenAPI spec detection, common API path probing,
  and GraphQL introspection. Use after web-crawling and js-analysis have produced endpoint
  candidates, to confirm and fully enumerate the API attack surface before vuln hunting.
  Do NOT use for exploiting discovered endpoints (auth bypass, IDOR, injection) — that's
  hunt phase work; this skill only maps what exists and what it accepts.
metadata:
  type: recon
  phase: mapped
  tools: [curl, ffuf, kiterunner, graphql-cop, postman]
depends_on: [web-crawling, js-analysis]
feeds_into: [surface-probes, hunt/*]
---

## Signals

- Endpoint candidates from `web-crawling`/`js-analysis` include `/api/`, `/v1/`, `.json` paths.
- Target is a known SPA/mobile-backed app (these almost always have a REST or GraphQL API).
- Need to confirm whether a Swagger/OpenAPI doc or GraphQL endpoint is exposed.

## Prerequisites

- `likely-api-endpoints.txt` from `web-crawling`, plus any endpoints from `js-analysis`.

## Methodology

1. Probe common Swagger/OpenAPI documentation paths directly:
   ```bash
   for p in swagger.json swagger.yaml openapi.json openapi.yaml api-docs swagger-ui.html \
            api/swagger.json v1/swagger.json .well-known/openapi.json; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com/$p")
     echo "$code  /$p"
   done
   ```
2. If a spec is found, pull it and enumerate every defined route + parameter — this is the
   single highest-value API recon step when available:
   ```bash
   curl -s https://example.com/api/swagger.json -o swagger.json
   jq '.paths | keys' swagger.json
   # or load into Postman/Insomnia for interactive exploration
   ```
3. Probe common REST path/verb patterns where no spec is published:
   ```bash
   ffuf -u "https://example.com/api/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -mc 200,201,204,301,302,401,403 -o ffuf-api.json -of json
   ```
4. kiterunner for API-route brute force using realistic route wordlists derived from common
   framework patterns and known API specs (notably effective against REST APIs with
   predictable CRUD routes):
   ```bash
   kr scan https://example.com -w routes-large.kite -x 10 -j -o kiterunner-results.json
   ```
5. GraphQL introspection — if a `/graphql` endpoint exists, introspection (if not disabled)
   dumps the entire schema including fields not used by the frontend:
   ```bash
   curl -s -X POST https://example.com/graphql -H "Content-Type: application/json" \
     -d '{"query":"{__schema{types{name,fields{name}}}}"}' | jq .
   ```
   Or with a dedicated tool for a cleaner schema dump and known-misconfig checks:
   ```bash
   graphql-cop -t https://example.com/graphql -o graphql-cop-results.json
   ```
6. If introspection is disabled, try common endpoint variants and check for verbose errors
   that leak schema hints:
   ```bash
   for p in graphql graphql/v1 api/graphql v1/graphql graphiql; do
     curl -s -o /dev/null -w "%{http_code}  /$p\n" "https://example.com/$p"
   done
   ```
7. Check for API versioning differences — an older/deprecated version (`/v1/` vs `/v2/`)
   may lack protections added later:
   ```bash
   for v in v1 v2 v3 beta internal; do
     curl -s -o /dev/null -w "%{http_code}  /$v/users\n" "https://example.com/api/$v/users"
   done
   ```

## Tooling

`curl`, `ffuf -mc` with API-specific wordlists (SecLists `Discovery/Web-Content/api/`),
`kiterunner` (`kr scan -w`), `jq` for spec parsing, `graphql-cop`, Postman/Insomnia for manual
spec-driven exploration.

## Validation gate

- [ ] Any discovered spec (Swagger/OpenAPI/GraphQL schema) saved as a raw artifact, not
      just summarized — it's the authoritative map of attack surface for hunting.
- [ ] Every discovered route recorded with method, auth requirement observed (401/403 vs 200),
      and response code — this is the MAPPED-phase inventory `engagement-flow` expects.
- [ ] GraphQL introspection result (enabled/disabled) explicitly noted either way.

## Gotchas

- An exposed Swagger/OpenAPI doc on a production host is itself often a legitimate finding
  (information disclosure) even before using it to find other bugs — don't just treat it
  as a recon convenience and forget to note the exposure itself.
- GraphQL introspection being disabled doesn't mean the schema is hidden — field suggestion
  via error messages, or a batched/aliased query, can still reveal structure; this is a
  hunt phase technique, not something to force through during mapping.
- Hidden/internal API versions (`/internal/`, `/admin/api/`) found via js-analysis are
  frequently unauthenticated by oversight — map them here, exploit them only after
  confirming scope and getting any required sign-off for auth-bypass testing.
- Rate limiting on brute-forced API path guessing applies just like any other fuzzing —
  follow `opsec-discipline` concurrency/delay settings, not ffuf's aggressive defaults.
- **SPA fallback false positives:** Many SPAs (Next.js, React Router, Vue Router)
  return 200 + their `index.html` for ANY path, including `/graphql`, `/api/anything`,
  etc. A 200 alone does NOT confirm the endpoint exists. Always check
  `Content-Type`: if it's `text/html` on a path that should return JSON/GraphQL,
  it's the SPA catch-all, not a real API endpoint. Verify with:
  ```bash
  ct=$(curl -sk -o /dev/null -w '%{content_type}' "https://{host}/graphql")
  echo "$ct"  # text/html → SPA fallback, application/json → real endpoint
  ```
  A 405 (Method Not Allowed) is actually a stronger signal than 200 — it means
  the path exists but the method is wrong (try POST for GraphQL).
