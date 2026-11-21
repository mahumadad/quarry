---
name: parser-desync
description: >
  Exploit parser discrepancies between a front layer (WAF/proxy/gateway) and the backend when
  they disagree on how to read the SAME body or path: duplicate JSON keys, multipart boundary
  and part-header handling, encoding normalization (%00, overlong UTF-8, charset), and path
  normalization (..;/, double slash, dot-segments). Use when a request traverses more than one
  parser (CDN/WAF → origin, gateway → service) and a security decision depends on parsed content.
  Keywords: parser discrepancy, parser desync, json interoperability, duplicate keys, multipart
  confusion, content-type confusion, encoding normalization, path normalization, waf bypass by
  parsing, charset confusion.
  Do NOT use for HTTP message-framing desync (CL.TE/TE.CL/H2) — use http-smuggling.
  Do NOT use for same-layer parameter precedence alone — use parameter-pollution.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-436, CWE-444, CWE-20]
  mitre_attack: [T1027]
  tools: [burp, curl, python]
depends_on: [http-smuggling, parameter-pollution, tech-stack-fingerprint]
feeds_into: [chain-analysis, auth-bypass]
chains_with: [http-smuggling, parameter-pollution, auth-bypass, broken-access-control]
---

## Signals

- A request demonstrably crosses more than one parser: CDN/WAF in front of an origin, an API
  gateway in front of microservices, a reverse proxy doing auth/routing before the app.
- A security decision (auth, routing, WAF rule, access check) is made on a value that the
  backend later re-parses — the precondition for the two layers to disagree.
- Mixed stacks between layers (e.g. an nginx/Go edge and a Node/Express or Java/Spring origin)
  whose JSON/multipart/encoding behaviors are known to differ.

## Prerequisites

- Enough stack fingerprinting (`tech-stack-fingerprint`) to know, or hypothesize, which parser
  sits at each layer — the attack is about *which two* disagree and how.
- A value whose parsed result changes a decision: a role/tenant field the WAF inspects and the
  app trusts, a path the proxy authorizes and the app serves, a filename the edge filters.
- A baseline of the normal request so each discrepancy test is a single controlled change.

## Methodology

1. **Map the layers and pick the decision point.** Identify what the front layer decides
   (block rule, route, auth) and what the backend independently re-parses. The target is a field
   or path where "front sees X, backend sees Y".

2. **Duplicate JSON keys.** Send the same key twice with different values and observe which layer
   honors which occurrence (first vs last vs merged vs error):
   ```bash
   curl -s https://target/api/action -H 'Content-Type: application/json' \
     --data '{"role":"user","role":"admin"}'
   ```
   A WAF that reads `role=user` while the backend reads `role=admin` is an authorization-relevant
   desync. Also test nested duplicates and type confusion (`{"role":"user","role":["admin"]}`).

3. **Content-Type / charset confusion on one endpoint.** Submit the same endpoint as JSON, then as
   form-encoded, then with an unexpected or dual `Content-Type`, or an odd `charset`:
   ```bash
   curl -s https://target/api/action -H 'Content-Type: application/json; charset=utf-7' \
     --data '{"role":"admin"}'
   ```
   Some edges only apply JSON body rules to `application/json`; flipping the declared type can
   route the body past the inspecting parser into a backend that still parses it.

4. **Multipart boundary / part-header discrepancies.** Vary the `boundary` (duplicate boundary
   params, whitespace, missing quotes), repeat part names, and vary each part's `Content-
   Disposition`/`Content-Type`. Front and backend multipart parsers frequently split parts
   differently — use it to smuggle a second `filename`/field past an upload or field filter.

5. **Encoding normalization.** Probe `%00` truncation, overlong/invalid UTF-8, and double/mixed
   URL-encoding in security-relevant values (filenames, extensions, role strings). A front layer
   that filters `...evil.php` may pass `...evil.php%00.jpg` that the backend truncates to `.php`.

6. **Path normalization.** Test `..;/`, `//`, `/./`, `%2e%2e%2f`, trailing-dot and case variants
   on an access-controlled path:
   ```bash
   curl -s https://target/admin/..;/admin/users      # proxy authorizes /admin/..;/ ... origin serves /admin/users
   curl -s https://target//admin//users
   ```
   The finding is a path the proxy authorizes/blocks under one normalization while the origin
   resolves it to a different, access-controlled resource.

7. **Body-size inspection window (nowafpls) + method/header multiplicity.** Most commercial
   WAFs only inspect the first N KB of a body (8-128 KB by tier), so padding benign filler past
   that window slips the real payload past inspection while the backend still parses the whole
   body. Also flip the method (a blocked `GET` param re-sent as a `POST` body, or vice-versa)
   and send a duplicate same-name `Content-Type` (edge reads the first, backend the last). The
   engine builds the oversized body for you:
   ```bash
   # engine/defense_evasion.py: WAFBypassEngine().generate_oversized_body(payload, pad_to=65536)
   # pad to 8/16/32/64/128 KB; set Content-Length to the real total; keep filler benign (A/space)
   python3 -c "from engine.defense_evasion import oversized_body_pad as p; print(p(\"' OR 1=1--\", 65536))" \
     | curl -s -i -X POST --data-binary @- -H 'Content-Type: application/x-www-form-urlencoded' https://target/login
   ```

8. **Confirm the disagreement, not just the odd response.** For every candidate, show the two
   layers reached *different* conclusions on the *same* bytes — e.g. the WAF logged/blocked value
   X while the application acted on value Y, or the proxy 403'd one spelling while another reached
   a protected handler.

## Tooling

- Burp Repeater — the core manual tool for byte-level single-variable tests across layers.
- `curl` with `--data-raw` / explicit headers — scriptable discrepancy probes.
- A small python harness emitting malformed JSON/multipart (raw bytes, not a library that
  "helpfully" normalizes) so you control exactly what each layer receives.

## Payloads & Detection Patterns

Guía de caza para el desync de *parsers* (no de framing: CL.TE/TE.CL/H2 framing va a
`http-smuggling`). Una familia por discrepancia de contenido/ruta; la prueba es siempre que las
*dos* capas leyeron los mismos bytes distinto y eso cambió una decisión.

| Categoría | Shape | Propósito |
|---|---|---|
| Duplicate JSON keys | `{"role":"user","role":"admin"}`, type confusion `{"role":"user","role":["admin"]}` | Front honra una ocurrencia, backend otra (precedencia divergente) |
| HTTP/2 downgrade | Request H2 reescrita a H1 en el edge con header/pseudo-header que cambia normalización | Edge normaliza distinto que el origin al bajar de versión |
| Header normalization | Header duplicado, obs-fold (continuación con espacio), underscore↔dash (`X_Forwarded_For` vs `X-Forwarded-Host`), case | Una capa fusiona/descarta, la otra lee la variante contraria |
| Chunk parsing divergente | `chunk-size` con espacios/comentario, trailers, `0\r\n` adelantado | Parser lenient vs strict (framing crudo → remite a `http-smuggling`) |
| Content-Type/charset confusion | `application/json; charset=utf-7`, dual `Content-Type`, type inesperado | Body salta la capa que solo inspecciona `application/json` |
| Multipart boundary/part | Boundary duplicado/whitespace/sin comillas, part names repetidos, doble `filename` | Split de partes distinto → cuela segundo campo/archivo |
| Encoding normalization | `%00` truncation, overlong/invalid UTF-8, double/mixed URL-encode `%252e` | Filtro de extensión/rol evadido por normalización asimétrica |
| Path normalization | `..;/`, `//`, `/./`, `%2e%2e%2f`, trailing-dot/case | Proxy autoriza una forma, origin resuelve otra (recurso protegido) |

Surface signals que delatan la clase antes de probar:
- Dos parsers conocidos distintos en el path (nginx/Go edge + Node/Express o Java/Spring origin).
- Una decisión de seguridad (auth/route/WAF/filtro) tomada en la capa frontal y re-parseada por el backend.
- Headers con underscore aceptados, `Content-Type` flexible, o `200` ante JSON/multipart malformado.

```bash
# Duplicate-key precedence: observar qué valor actúa (front vs backend)
curl -s https://target/api/action -H 'Content-Type: application/json' \
  --data '{"role":"user","role":"admin"}'                 # ¿la app actúa como admin?

# Content-Type flip: mismo body, tipo declarado distinto
curl -s https://target/api/action -H 'Content-Type: application/json; charset=utf-7' \
  --data '{"role":"admin"}'                                # ¿el WAF deja de inspeccionar?

# Path normalization contra ruta con control de acceso
curl -s -o /dev/null -w '%{http_code}\n' https://target/admin/users          # control (bloqueado)
curl -s -o /dev/null -w '%{http_code}\n' "https://target/admin/..;/admin/users"  # ¿origin resuelve?
```

## Bypass Techniques

Agrupadas por la defensa de la capa frontal que evaden; la nota es la condición que delata cada una.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Regla WAF sobre JSON body | Flip de `Content-Type` a form/charset raro, dual CT | El edge solo aplica reglas JSON a `application/json` |
| Filtro de extensión en upload | `evil.php%00.jpg`, doble `filename` en multipart, overlong UTF-8 | Backend trunca o elige una parte distinta a la que vio el edge |
| ACL de path en proxy | `..;/`, `%2e%2e%2f`, `//`, `/./`, trailing-dot | Origin normaliza a un recurso protegido que el proxy no autorizó |
| Auth por header en el edge | Underscore/case/obs-fold del header de identidad | Backend lee la variante que el edge no normalizó |
| Dedup de clave por el WAF | Duplicate key con precedencia opuesta a la del backend | WAF lee la primera, la app la última (o viceversa) |
| H2-only WAF rule | Enviar H2 que al downgrade a H1 cambia el framing/normalización | La regla inspecciona H2, el origin ve la forma H1 reescrita |

## Root Causes

- Two parsers in the path implement the same spec differently (duplicate-key policy, multipart
  boundary edge cases, Unicode/percent-decoding, path dot-segment handling).
- A security control parses defensively at the edge but the backend re-parses with different
  rules, so the edge's view is not the view the app acts on.
- Charset/content-type assumptions let a body skip the layer that was supposed to inspect it.

## Validation Gate (minimum proof)

- Evidence that the front layer and the backend parsed the same request differently in a way that
  changed a security decision: a value the WAF saw vs the value the app acted on, or a path the
  proxy authorized vs the resource the origin served — both observations captured.
- A concrete impact: WAF rule bypassed, an access-controlled path reached, a field filter evaded,
  or an upload filter bypassed — not merely "the server accepted weird input".

## Gotchas

- **Two layers, one body.** The finding requires an actual disagreement between layers; a single
  app tolerating malformed input (with no security decision upstream) is at most robustness, not a
  desync finding.
- **Not message framing.** Request/response smuggling via `Content-Length`/`Transfer-Encoding`/H2
  is `http-smuggling`; keep framing desync there and content/path parsing here.
- **Common N/A:** both layers reject the malformed request identically — control working; record
  as coverage.
- **Overclaim trap:** a `200` on malformed JSON is not a finding unless you show it flipped a
  decision (auth/route/filter). Pair every probe with the decision it was meant to subvert.
- Libraries in your own tooling may normalize the payload before it leaves your machine — send
  raw bytes and verify on the wire that the backend actually received the malformed form.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Decision flipped** — Which security decision (auth, route, WAF rule, filter) did the
   discrepancy actually change?
2. **Reach** — Does the path/body desync reach an access-controlled resource or action, not just
   a harmless endpoint?
3. **Filter bypass** — Can it carry a payload for another class (XSS/SQLi/upload) past the edge
   filter that would otherwise block it?
4. **Generality** — Does the discrepancy hold across endpoints/methods, or only the one tested?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- parser-desync → **auth-bypass** / **broken-access-control** when a path/body discrepancy reaches
  a protected handler.
- parser-desync as a delivery wrapper → **http-smuggling** findings, or carrying XSS/SQLi/upload
  payloads past an edge WAF (feeds the relevant hunt skill).
- parser-desync + **parameter-pollution** when duplicate-key precedence differs across layers.
