---
name: springboot
description: >
  Hunt for Spring Boot / Spring weaknesses: exposed Actuator endpoints (/env, /heapdump,
  /gateway, /mappings, /loggers), SpEL expression injection, H2 console RCE, Spring4Shell RCE
  (CVE-2022-22965) and Spring Cloud Gateway SpEL RCE (CVE-2022-22947), and Java deserialization.
  Use when the target is Spring (Whitelabel Error Page, /actuator, X-Application-Context, Spring
  Security 401 JSON, jsessionid). Keywords: spring boot, spring, actuator, /env, heapdump, h2
  console, spel injection, spring4shell, CVE-2022-22965, CVE-2022-22947, spring cloud gateway,
  jolokia, java deserialization, whitelabel error.
  Do NOT use for language-agnostic deserialization theory (use deserialization) or generic SSRF
  (use ssrf). This is the Spring-specific Actuator/SpEL/H2 surface.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-200, CWE-917, CWE-502, CWE-94, CWE-215]
  mitre_attack: [T1190, T1212, T1552.001]
  tools: [curl, ysoserial, nuclei, spring-boot-actuator-exploit, burp]
depends_on: [active-recon, tech-stack-fingerprint, info-disclosure]
feeds_into: [chain-analysis, rce, info-disclosure]
chains_with: [deserialization, rce, ssrf, info-disclosure, credential-testing]
---

## Signals

- Spring fingerprints: default "Whitelabel Error Page", `X-Application-Context` header, a Spring
  Security 401/403 JSON body (`{"timestamp":...,"status":401,"error":"Unauthorized"}`),
  `Set-Cookie: JSESSIONID=`, `/actuator` responding.
- Actuator discovery: `/actuator` returns a `_links` HAL document listing `env`, `health`,
  `heapdump`, `mappings`, `loggers`, `gateway`, `beans`, `threaddump`, `jolokia`.
- A `/h2-console` login form (H2 database web console) reachable.
- Spring Cloud Gateway in use (`/actuator/gateway/routes`, gateway route filters) — SpEL RCE
  surface (CVE-2022-22947).
- A form/endpoint that binds request params to a Java bean (`@ModelAttribute`, data binding) —
  the Spring4Shell `class.module.classLoader` surface.

## Prerequisites

- Confirmed Spring Boot (Whitelabel page or `/actuator` HAL links).
- For Actuator leaks: the sensitive endpoints reachable without auth (default-exposed or
  `management.endpoints.web.exposure.include=*`).
- For Spring4Shell (CVE-2022-22965): a JDK 9+ app deployed as a WAR on Tomcat with
  `@RequestMapping` data binding to a POJO — the classic preconditions; outside them it is
  Unproven.
- For SpEL / Gateway / H2 RCE: the specific feature present (a SpEL-evaluating param, Spring Cloud
  Gateway actuator, or an H2 console accepting connection URLs).
- OOB listener with per-attempt token for blind RCE confirmation (`engine.oast`).

## Methodology

1. **Fingerprint and enumerate Actuator.** Pull the HAL index and probe sensitive endpoints:
   ```bash
   curl -s https://target/actuator | python3 -m json.tool 2>/dev/null | grep -oE '"[a-z]+":'
   # common base paths differ by version: /actuator/<x> (Boot 2/3) vs /<x> (Boot 1)
   for e in env health info mappings beans loggers heapdump threaddump httptrace configprops gateway; do
     echo "$e -> $(curl -s -o /dev/null -w '%{http_code}' https://target/actuator/$e)"
   done
   ```

2. **`/actuator/env` and config leaks.** `env` dumps properties — often DB creds, API keys, and
   cloud secrets (masked by default in newer versions, but frequently unmasked):
   ```bash
   curl -s https://target/actuator/env | grep -oE '"(password|secret|key|token|uri)":[^,]+' | head
   curl -s "https://target/actuator/env/spring.datasource.password"     # single-property read
   curl -s https://target/actuator/configprops | head -c 800
   ```
   Real secret values here are info-disclosure (critical) and feed credential reuse.

3. **`/actuator/heapdump`.** A heap dump is a full memory snapshot — session tokens, credentials,
   in-flight secrets:
   ```bash
   curl -s https://target/actuator/heapdump -o heapdump.hprof   # large; download is a Human-gate action — confirm first
   # analyze locally for secrets (e.g. with VisualVM / a strings sweep)
   strings heapdump.hprof | grep -iE 'password=|authorization: bearer|aws_secret|jdbc:'
   ```
   Downloading is a byte-exfiltration step — get the operator gate before pulling the file.

4. **`/actuator/env` write → RCE pivots.** On older Boot with a writable env and certain beans, a
   POST to `env` can set properties that trigger code paths (e.g. `spring.cloud.bootstrap`, JNDI via
   a datasource/logging property). Confirm the endpoint is writable first:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target/actuator/env \
     -H 'Content-Type: application/json' -d '{"name":"qz.probe","value":"1"}'
   curl -s https://target/actuator/env/qz.probe    # readback => env is writable (RCE pivot surface)
   ```
   Any JNDI/datasource property manipulation that reaches code execution is a gated action — prove
   reachability, then stop for the operator gate.

5. **Spring Cloud Gateway SpEL RCE (CVE-2022-22947).** If the gateway actuator is enabled, a route
   with a malicious SpEL filter can be added and refreshed to execute code:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://target/actuator/gateway/routes   # enabled?
   # the published PoC POSTs a route whose filter contains a SpEL #{T(java.lang.Runtime)...} payload,
   # refreshes, then requests the route; use a benign OOB command and poll
   python3 -m engine.oast poll --audit-dir .
   ```
   This mutates gateway routes (state change) — a Human-gate action; confirm scope before the full
   chain and clean up any added route.

6. **SpEL injection (generic).** Where user input reaches `SpelExpressionParser` (query DSLs,
   `@Value`, some search/sort params), a SpEL payload evaluates server-side:
   ```bash
   curl -s "https://target/search?q=\${7*7}"                 # property-placeholder style
   curl -s "https://target/x?expr=T(java.lang.Runtime)"      # SpEL type reference probe
   # arithmetic oracle first; RCE via T(Runtime).getRuntime().exec only behind a gate + OOB proof
   ```
   `49` or a type-reference behaviour change identifies SpEL; escalate only under authorization.

7. **H2 console RCE.** An exposed `/h2-console` lets you set a JDBC URL with an INIT script that
   runs Java — a well-known RCE:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://target/h2-console       # form present?
   # the attack sets jdbc:h2:mem:test;INIT=CREATE ALIAS ... AS '...Runtime.exec...' and connects;
   # prove with an OOB callback, treat the connect as a gated state-changing action
   ```

8. **Spring4Shell (CVE-2022-22965).** Under the WAR-on-Tomcat/JDK9+ data-binding preconditions, a
   crafted `class.module.classLoader.*` param set writes a JSP webshell:
   ```bash
   # safe reachability probe: does binding class.module.classLoader.* change behaviour / error?
   curl -s -o /dev/null -w "%{http_code}\n" "https://target/path?class.module.classLoader.DefaultAssertionStatus=qz"
   # the public PoC sets AccessLogValve properties to drop a JSP; treat the webshell write as a
   # gated action and prefer a benign marker over a live shell
   ```
   Confirm the deployment model (WAR/Tomcat) — a JAR/embedded-Tomcat app with no POJO binding is
   generally not exploitable; a version match alone is Unproven.

9. **Confirm the primitive and stop at the gate.** Record which path (Actuator leak, env write,
   Gateway SpEL, generic SpEL, H2 console, Spring4Shell, deserialization). Heap-dump download,
   route mutation, webshell write, and credential use are Human-gate / new-scope actions.

## Tooling

- `curl` / Burp — enumerate Actuator, read `env`, probe SpEL/data-binding params.
- `nuclei -tags spring,actuator` — triage exposed-actuator and Spring CVE templates (confirm
  preconditions; don't report on version match alone).
- `ysoserial` — Java gadget chains for any Spring deserialization sink (verify payload class with
  the target's libs; overlaps deserialization).
- `spring-boot-actuator-exploit` / jolokia tooling — automate env/jolokia-based pivots (verify
  flags with `-h`).
- `engine.oast` / `interactsh` — OOB proof for SpEL/Gateway/H2/Spring4Shell RCE.
- VisualVM / `strings` — mine a heap dump for secrets (post-gate, locally).

## Root Causes

- Actuator sensitive endpoints exposed to the web (`exposure.include=*`, no Spring Security on the
  management port/path) — `env`/`heapdump`/`configprops` leak secrets; `gateway`/`env` enable
  pivots.
- User input evaluated as a SpEL expression (`SpelExpressionParser` on untrusted data), by design
  or via a vulnerable component (Spring Cloud Gateway CVE-2022-22947).
- Unauthenticated/exposed H2 console allowing arbitrary JDBC URLs with INIT scripts.
- Spring MVC/WebFlux data binding over `class.module.classLoader.*` on a WAR/Tomcat/JDK9+ deploy
  (CVE-2022-22965).
- Java deserialization of untrusted input in a Spring endpoint/message listener (gadget surface).

## Validation Gate (minimum proof)

- **Demonstrated:** `/actuator/env`/`configprops` returning real secret values; a `/actuator/heapdump`
  downloaded and shown to contain credentials/tokens (post-gate); a token-correlated OOB callback
  from Gateway SpEL / generic SpEL / H2 console / Spring4Shell (RCE); or a writable `env` confirmed
  by readback. Payload + request/response included.
- **Inferred:** an Actuator endpoint reachable but secrets masked; a SpEL `7*7`→`49` arithmetic
  oracle with no process reach yet; Spring4Shell `class.module.classLoader` binding accepted
  (behaviour change) but no webshell proven; a gateway actuator enabled but the route-filter chain
  not driven.
- **Unproven:** "Spring version X, therefore Spring4Shell/CVE-2022-22947" with no reproduced trigger
  and no matching deployment preconditions; `/actuator` present but all sensitive endpoints 403.
  Do not report as RCE.
- Name the vector precisely (Actuator leak vs env-write vs Gateway SpEL vs generic SpEL vs H2 vs
  Spring4Shell vs deserialization) — severity and fix differ.

## Payloads & Detection Patterns

Guía de caza: una familia por primitiva de Spring. El RCE (SpEL, Gateway, H2, Spring4Shell) es
ciego: el único camino a `Demonstrated` es un callback OOB correlacionado por token.

| Categoría | Shape | Propósito |
|---|---|---|
| Actuator discovery | `GET /actuator` (HAL `_links`) | Enumerar endpoints expuestos |
| env secret leak | `GET /actuator/env`, `/actuator/env/<prop>` | Credenciales/claves en properties |
| heapdump leak | `GET /actuator/heapdump` | Snapshot de memoria (tokens/creds) — gated |
| env write pivot | `POST /actuator/env {name,value}` + readback | Env escribible → pivote a ejecución |
| Gateway SpEL RCE | ruta con filtro SpEL `#{T(java.lang.Runtime)...}` + refresh | CVE-2022-22947 |
| Generic SpEL | `?expr=T(java.lang.Runtime)`, `${7*7}` | Inyección de expresión SpEL |
| H2 console RCE | JDBC URL con `INIT=CREATE ALIAS ... Runtime.exec` | RCE vía consola H2 |
| Spring4Shell | `class.module.classLoader.*` binding | CVE-2022-22965 (WAR/Tomcat/JDK9+) |

Surface signals que delatan la clase antes de inyectar:
- URL: `/actuator*`, `/h2-console`, `/actuator/gateway/routes`, `/actuator/jolokia`.
- HTML/JSON: "Whitelabel Error Page", 401 JSON de Spring Security, `_links` HAL.
- Headers: `X-Application-Context`, `Set-Cookie: JSESSIONID`.

```bash
# enumeración de Actuator (barrido corto de códigos)
for e in env health heapdump mappings configprops gateway/routes jolokia; do
  echo "$e -> $(curl -s -o /dev/null -w '%{http_code}' https://target/actuator/$e)"
done
```

```bash
# ¿env filtra secretos sin enmascarar?
curl -s https://target/actuator/env | grep -oiE '"(password|secret|token|key)":"[^*][^"]+"' | head
```

```bash
# SpEL oracle aritmético (no destructivo) antes de cualquier intento de ejecución
curl -s "https://target/search?q=\${7*7}" | grep -o '49' | head -1
```

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Base path desconocido | Probar `/actuator/<x>` (Boot 2/3) y `/<x>` (Boot 1); puerto de management aparte | La exposición cambia por versión |
| env enmascarado | `GET /actuator/env/<prop>` individual, o `/configprops`, o heapdump | A veces una ruta no aplica el masking |
| Spring Security en `/actuator` | `//actuator`, `/actuator/`, `;/`, case, encoding del path | El matcher de seguridad normaliza distinto al dispatcher (ver 403-bypass) |
| Gateway no listado | Probar `refresh` + `routes` aunque no aparezca en `_links` | `_links` puede ocultar endpoints habilitados |
| SpEL con sandbox | `T(java.lang.Runtime)`, `new ProcessBuilder(...)`, reflection vía `T(...)` | La sintaxis depende del contexto de evaluación |
| Spring4Shell patch parcial | Variar los props de `AccessLogValve` / usar otro pipeline bindable | Requiere las precondiciones WAR/Tomcat reales |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Actuator env/heapdump → credential reuse** — Do leaked DB/cloud/API secrets work elsewhere?
   Chain credential-testing (gate before use).
2. **env write / Gateway actuator → rce** — Is `env` writable or the gateway actuator enabled to
   reach SpEL execution? Reproduce with an OOB callback; gate state changes and clean up.
3. **SpEL / H2 / Spring4Shell → rce** — Does the arithmetic/type-reference oracle escalate to
   `Runtime.exec`? Gate before a real command.
4. **heapdump → session hijack** — Does the dump contain live JSESSIONID/bearer tokens? Chain
   auth-bypass.
5. **Actuator leak → internal pivot / ssrf** — Do `mappings`/`configprops` reveal internal
   services or URLs reachable via an SSRF primitive? Chain ssrf.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- `/actuator/env`/`heapdump` secret leak → **info-disclosure** → **credential-testing** → lateral
  access (new scope).
- Writable `/actuator/env` or Spring Cloud Gateway actuator → SpEL → **rce** (OOB-proven, gated).
- Generic SpEL / H2 console / Spring4Shell → **rce** (gated) → **post-exploitation**.
- Java deserialization sink → **deserialization** → **rce**.
- heapdump → live session tokens → **auth-bypass** / session hijack.
- `mappings`/`configprops` revealing internal URLs → **ssrf** internal pivot.

## Gotchas

- **Version match is Unproven.** Spring4Shell (CVE-2022-22965) and Gateway SpEL (CVE-2022-22947)
  have hard preconditions (WAR/Tomcat/JDK9+ for the former; gateway actuator enabled for the
  latter). A version banner is a lead; reproduce the trigger with an OOB callback before claiming
  RCE.
- **OOB proof, benign command, gate state changes.** Gateway-route mutation, H2 connect, and
  Spring4Shell webshell writes change target state — Human-gate actions; prove with a DNS/HTTP
  callback and clean up any added route/file.
- **env masking varies.** Newer Boot masks `password`/`secret` values as `******`; a masked `env`
  is Inferred, not a secret leak. Try single-property reads and `configprops`, but don't report
  masked output as a leak.
- **Heapdump download is exfiltration.** Pulling the `.hprof` moves potentially large sensitive
  data — confirm scope first; analyze locally, not on the target.
- **Common N/A:** `/actuator` present but all sensitive endpoints 403, SpEL probe not evaluated,
  H2 console 404, JAR/embedded-Tomcat deploy (Spring4Shell N/A) — record tested-and-safe.
- **Overclaim trap:** `7*7`→`49` proves SpEL evaluation, not `Runtime.exec`. Don't jump from the
  arithmetic oracle to "RCE" without the process-level step and a gate.
