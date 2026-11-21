---
name: cors
description: >
  Hunt for CORS misconfiguration: origin reflection with credentials, null-origin
  acceptance, and overly broad subdomain wildcard trust. Use when evaluating any API that
  sets Access-Control-Allow-Origin, especially endpoints returning sensitive/authenticated
  data consumed cross-origin.
  Keywords: cors, cross-origin resource sharing, access-control-allow-origin, origin
  reflection, null origin, credentialed request, subdomain takeover CORS trust,
  access-control-allow-credentials.
  Do NOT use for CSRF (CORS misconfig is a read-primitive, CSRF is a write-forgery primitive
  — they're related but distinct; cross-reference csrf when a CORS gap also enables
  state-changing cross-origin writes). Do NOT use for generic missing-security-header
  findings unrelated to CORS — use info-disclosure.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-942]
  mitre_attack: [T1190]
  tools: [curl, burp]
depends_on: [active-recon, web-crawling, fuzzing]
feeds_into: [chain-analysis, session-hijack]
chains_with: [csrf, info-disclosure, xss]
---

## Signals

- API responses containing `Access-Control-Allow-Origin` that mirrors the request's `Origin`
  header value exactly (origin reflection) rather than a fixed allowlisted value.
- `Access-Control-Allow-Credentials: true` present alongside any form of broad/reflected origin
  trust — this combination is what actually makes CORS misconfig exploitable for data theft
  (without credentials, cross-origin read access is far less impactful for session-bound data).
- Endpoints returning authenticated/sensitive JSON that would be worth stealing cross-origin
  (user profile, account data, API tokens, internal config).
- Wildcard subdomain trust (`*.target.com` effectively trusted) combined with any subdomain
  takeover risk or a subdomain hosting user-generated/attacker-reachable content (dev/staging
  subdomains, old marketing pages).

## Prerequisites

- An endpoint that returns sensitive data and sets CORS headers at all (if no
  `Access-Control-Allow-Origin` header is ever present, the browser's same-origin policy
  already blocks cross-origin JS reads by default — confirm the header is actually present
  before investing further).
- A valid authenticated session/cookie for the credentialed-request test.
- Ability to host a simple PoC page cross-origin (local file or your own domain) to prove actual
  browser-enforced impact, not just header inspection via curl.

## Methodology

1. **Baseline header inspection** — send requests with varying `Origin` headers and observe how
   `Access-Control-Allow-Origin`/`-Allow-Credentials` respond:
   ```bash
   curl -s -I https://target/api/profile -H "Origin: https://evil.test"
   curl -s -I https://target/api/profile -H "Origin: null"
   curl -s -I https://target/api/profile -H "Origin: https://target.com.evil.test"
   curl -s -I https://target/api/profile -H "Origin: https://sub.target.com"
   ```
   Look specifically for:
   ```text
   Access-Control-Allow-Origin: https://evil.test      <- reflects ANY origin = high risk
   Access-Control-Allow-Origin: null                    <- trusts null origin = high risk
   Access-Control-Allow-Credentials: true                <- combined with either above = exploitable
   ```

2. **Confirm reflection is unconditional** (not just matching an actual allowlisted partner
   domain) by trying a clearly unrelated, attacker-controlled-style origin:
   ```bash
   curl -s -I https://target/api/profile -H "Origin: https://attacker-controlled-poc.test"
   ```
   If this exact arbitrary string comes back in `Access-Control-Allow-Origin`, it's
   unconditional reflection — the strongest form of this bug.

3. **Null-origin test** — relevant because `Origin: null` is sent by browsers in several
   contexts attackers can trigger (sandboxed iframes, `file://` pages, some redirect chains):
   ```bash
   curl -s -I https://target/api/profile -H "Origin: null"
   ```

4. **Subdomain-wildcard trust test** — check if the allowlist logic is a loose regex/substring
   match rather than exact domain matching:
   ```bash
   curl -s -I https://target/api/profile -H "Origin: https://notarget.com"
   curl -s -I https://target/api/profile -H "Origin: https://target.com.attacker.test"
   curl -s -I https://target/api/profile -H "Origin: https://eviltarget.com"
   curl -s -I https://target/api/profile -H "Origin: https://xtarget.com"
   ```
   A match on `target.com.attacker.test` or `eviltarget.com` reveals a broken regex (e.g.
   `/target\.com$/` without anchoring, or a naive `.includes("target.com")` check).

5. **Browser-based PoC to prove actual impact** (headers alone are a strong signal but the
   finding's proof bar is the real cross-origin read):
   ```html
   <!-- cors_poc.html -->
   <script>
   fetch("https://target/api/profile", { credentials: "include" })
     .then(r => r.text())
     .then(data => {
       document.body.innerText = data;
       // in a real PoC this would exfil to an attacker server instead of displaying
     });
   </script>
   ```
   Host this cross-origin (or open as a `file://` page, which sends `Origin: null`) **in a
   browser where you're also logged into target** and confirm the sensitive response body
   actually renders — this is what separates a real finding from a header-only observation.

6. **Preflight (`OPTIONS`) behavior check** for non-simple requests (custom headers, non-GET/
   POST methods):
   ```bash
   curl -s -X OPTIONS https://target/api/admin/users \
     -H "Origin: https://evil.test" \
     -H "Access-Control-Request-Method: DELETE" \
     -H "Access-Control-Request-Headers: Authorization" -i
   ```
   Check if `Access-Control-Allow-Methods`/`-Allow-Headers` permit state-changing methods from
   an arbitrary origin — this crosses into CSRF-adjacent impact (see Chains below).

## Tooling

- `curl -I` with varied `Origin` headers — the entire manual methodology above, no special
  tooling required for detection.
- Burp Suite — repeat the same header variations via Repeater; use the CORS-specific passive
  scan checks if the Pro scanner is in use (triage only, confirm manually).
- A minimal local HTML file opened in a real browser — required for the actual impact PoC,
  since curl doesn't enforce/exhibit the same-origin policy a victim's browser would.

## Payloads & Detection Patterns

Guía de caza: una familia por lógica de trust de origin. La inspección de headers por `curl` es
Inferred; el salto a Demonstrated exige un `fetch` cross-origin con `credentials:'include'` en un
browser real leyendo datos autenticados.

| Categoría | Shape | Propósito |
|---|---|---|
| Origin reflection | `Origin: https://evil.test` → ACAO refleja el mismo string | Reflejo incondicional = forma más fuerte del bug |
| Null origin | `Origin: null` → `ACAO: null` | Browser lo manda desde iframe sandbox/`file://`/redirects |
| Suffix match roto | `Origin: https://target.com.evil.test` | Regex sin anclar (`/target\.com$/` ausente) |
| Prefix/substring match roto | `Origin: https://eviltarget.com`, `https://xtarget.com` | `.includes("target.com")` ingenuo |
| Subdomain trust | `Origin: https://sub.target.com` (dev/staging tomable) | Confía `*.target.com` + XSS/takeover en subdominio |
| Credentialed combo | cualquiera de los anteriores + `ACAC: true` | Lo que hace explotable el robo de datos de sesión |

Surface signals que delatan la clase antes de montar el PoC:
- Respuestas con `Access-Control-Allow-Origin` que espeja el `Origin` enviado en vez de un valor fijo.
- `Access-Control-Allow-Credentials: true` junto a cualquier trust reflejado/amplio → combinación explotable.
- Endpoints que devuelven JSON autenticado/sensible (perfil, cuenta, tokens, config interna).
- Subdominios dev/staging o páginas viejas con contenido atacante-alcanzable bajo wildcard trust.

```bash
# barrido de origins (un string atacante inequívoco para descartar allowlist legítimo)
for o in https://attacker-poc.test null https://target.com.evil.test https://eviltarget.com; do
  echo "== $o =="
  curl -s -I https://target/api/profile -H "Origin: $o" \
    | grep -iE 'access-control-allow-(origin|credentials)'
done
```

```bash
# preflight: ¿permite métodos de escritura desde origin arbitrario? (cruza a CSRF)
curl -s -X OPTIONS https://target/api/admin/users -i \
  -H "Origin: https://evil.test" \
  -H "Access-Control-Request-Method: DELETE" \
  -H "Access-Control-Request-Headers: Authorization" \
  | grep -iE 'access-control-allow-(methods|headers|origin|credentials)'
```

## Bypass Techniques

Agrupadas por la validación de origin que evaden; probar la familia completa antes de cerrar.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Allowlist por sufijo | `https://target.com.evil.test` | Regex `target\.com` sin `$`/anclaje |
| Allowlist por prefijo | `https://target.com.attacker/` con host propio | Match al inicio sin verificar el resto |
| Allowlist por substring | `https://eviltarget.com`, `https://target.com.evil` | `includes()`/`indexOf()` sin boundaries |
| Rechazo de evil.test | `Origin: null` vía iframe sandbox/`file://`/redirect 307 | `null` suele estar allowlisted para casos legítimos |
| Trust de subdominio | XSS o subdomain takeover en `*.target.com` confiado | Encadena desde un subdominio controlado |
| Fix solo en HTTP | Endpoint WebSocket que omite la verificación CORS | WS no está sujeto a same-origin del mismo modo |
| CORS solo en 2xx | Forzar 4xx/5xx que igual lleve datos sensibles en el body | Headers CORS a veces faltan solo en el path de error |

## Root Causes

- CORS middleware configured to reflect the request's `Origin` header verbatim instead of
  checking it against a fixed allowlist (`cors({origin: true})` in Express, or equivalent
  patterns in other frameworks, often added to "just make CORS errors go away" during
  development and left in production).
- Null-origin explicitly allowlisted to support legitimate `file://`/sandboxed-iframe use
  cases, without recognizing it's also attacker-triggerable.
- Domain-matching logic using substring/regex checks instead of exact-match or a well-anchored
  regex against the full allowed domain list.
- `Access-Control-Allow-Credentials: true` set globally without re-examining whether the origin
  policy next to it is actually restrictive enough to pair with credential exposure.

## Validation Gate (minimum proof)

- A browser-executed cross-origin `fetch`/`XHR` with `credentials: 'include'` from a page NOT
  on the target's origin successfully retrieves authenticated, sensitive response data —
  captured as a screenshot or saved response showing real account data, not a generic/public
  endpoint.
- The specific `Origin` value tested and the exact `Access-Control-Allow-Origin` /
  `-Allow-Credentials` response headers, documented together — the combination is what
  constitutes the finding, not either header alone.

## Gotchas

- **Minimum proof, not a stolen-data archive.** Confirm the read works against your own test
  account's data; don't use the primitive to systematically pull other users' data even though
  the bug would allow it.
- **Common N/A:** `Access-Control-Allow-Origin` reflects the origin but
  `Access-Control-Allow-Credentials` is absent or `false` — for endpoints returning data behind
  cookie-based auth, this is a much weaker finding (no-credentials cross-origin reads only
  expose data the endpoint would serve unauthenticated anyway) — downgrade severity
  accordingly, don't report it at the same severity as the credentialed case.
- **Common N/A:** the endpoint being tested returns only public, non-sensitive data regardless
  of origin — a permissive CORS policy on a genuinely public API is by design, not a finding.
- **Overclaim trap:** observing origin reflection via `curl` alone, without the browser-executed
  PoC, is a strong *indicator* but should be labeled Inferred, not Demonstrated, until the
  actual cross-origin fetch is shown succeeding in a real browser context.
- **Overclaim trap:** a wildcard `Access-Control-Allow-Origin: *` is only exploitable for
  credentialed requests if credentials are also allowed — browsers actually reject
  `Allow-Credentials: true` paired with a literal `*` origin value per spec, so true
  `*` + credentials isn't achievable; that combination response is actually CORS failing safe,
  not a finding (the risk case is *reflected* origin + credentials, not literal wildcard +
  credentials).
- Some frameworks apply CORS headers only on the actual response but not consistently on error
  responses (4xx/5xx) — test both success and error paths if the sensitive data could leak via
  an error body too.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Authenticated data exfiltration** — Can you exfiltrate authenticated, session-bound data, not just already-public data?
2. **Reflected origin + credentials** — Does the server reflect an arbitrary Origin AND set Access-Control-Allow-Credentials: true? That combination is the actual vulnerability.
3. **Trusted subdomain XSS chain** — Is there an XSS on a subdomain the CORS policy trusts, that can be chained to exploit this origin?
4. **WebSocket bypass path** — Is there a WebSocket endpoint that skips CORS checks entirely, bypassing an HTTP-layer fix?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- CORS misconfig + credentials → direct session/data theft, feeds `session-hijack`/
  `chain-analysis`.
- CORS misconfig allowing credentialed reads of a CSRF-token-bearing page → defeats
  **csrf** token protections by letting the attacker read the token cross-origin before
  forging the write request.
- CORS misconfig on an endpoint also reachable via stored **xss** compounds severity
  (two independent paths to the same data theft) — note both but don't double-count as a single
  finding.
