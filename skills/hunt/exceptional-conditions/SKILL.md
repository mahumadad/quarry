---
name: exceptional-conditions
description: >
  Hunt for insecure handling of error and exceptional states: malformed/unexpected input that
  causes the app to fail OPEN (skip a check, grant access, return more data) or to leak internals
  (stack traces, framework/version, file paths, SQL, config, secrets) through error responses.
  Use when probing how an endpoint reacts to broken types, truncated bodies, oversized/edge
  values, wrong content-types, encoding tricks, and partial failures — the error path as the
  attack surface. Keywords: error handling, fail open, fail closed, stack trace, verbose error,
  exception, 500 internal server error, information leak, malformed input, type confusion, debug
  mode, unhandled exception.
  Do NOT use for a specific injection class that happens to error (that's sqli/nosqli/xxe/etc.) —
  this skill is about the error/exception behaviour itself: what leaks and what gets bypassed when
  the app breaks.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-209, CWE-755, CWE-248, CWE-636, CWE-703]
  mitre_attack: [T1190, T1592, T1211]
  tools: [curl, burp, ffuf, radamsa]
depends_on: [active-recon, web-crawling, fuzzing]
feeds_into: [chain-analysis, info-disclosure, auth-bypass]
chains_with: [info-disclosure, auth-bypass, business-logic]
---

## Signals

- Endpoints that return `500`/`502` with a body — any stack trace, exception class, file path,
  framework banner, or SQL fragment means verbose error handling is on.
- Branches where a check depends on a value that *could* be absent/null/malformed: "if the
  entitlement lookup throws, do we deny or do we continue?" (fail-open risk).
- Multi-step flows (payment, provisioning, upload) where a mid-step failure might leave the system
  in a permissive partial state (access granted but not revoked, record created but not validated).
- Debug/verbose modes toggled by header/param/host (`?debug`, `X-Debug`, dev subdomain) leaking
  internals.
- Inputs with strict "happy path" shapes — a type, a required field, a bounded number — where the
  unexpected shape has obviously not been considered.

## Prerequisites

- A baseline of the normal (happy-path) response for each target endpoint, so you can recognise
  both a leak (extra internals) and a fail-open (access/data you shouldn't get) against it.
- A set of malformation strategies ready: wrong types, null/empty/missing fields, truncated and
  oversized bodies, wrong/absent content-type, bad encodings, boundary numbers, duplicated params.
- A mutation/fuzzing tool (`radamsa`, Burp Intruder, `ffuf`) for scaling the malformed-input sweep.

## Methodology

1. **Baseline, then malform systematically.** For each parameter/body, send deliberately
   exceptional inputs and watch the response class and body:
   ```bash
   EP="https://target/api/v2/order"
   # type confusion: field expected as string → send array/object/number/null
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{"qty":"abc"}'
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{"qty":[1,2,3]}'
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{"qty":{"$":1}}'
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{"qty":null}'
   # structural: truncated JSON, missing required field, extra/duplicate keys
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{"qty":'
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{}'
   # wrong content-type / body mismatch
   curl -s -X POST $EP -H "Content-Type: application/xml" -d '{"qty":1}'
   ```
   Catalogue: `500` with a stack trace (leak), or — more interesting — a *success/permissive*
   response where you expected rejection (fail-open).

2. **Hunt the information leak.** Collect everything the error path reveals:
   ```bash
   # trigger and grep for internals
   curl -s -X POST $EP -H "Content-Type: application/json" -d '{"qty":[1]}' \
     | grep -ioE "at [a-z0-9_.]+\(|Exception|Traceback|/var/www|/home/|C:\\\\|SQLSTATE|org\.|com\.|line [0-9]+|version [0-9.]+"
   ```
   Stack traces reveal framework + version (CVE leads), file paths (LFI/structure), SQL (injection
   leads), internal hostnames, and sometimes secrets echoed from config/env.

3. **Hunt the fail-open.** The higher-impact half. Force the *security-relevant* operation to
   fail and see whether the app denies or proceeds:
   - Make an authorization/entitlement lookup error (malformed token claim, non-existent role id,
     oversized identifier) — does the request get denied, or does the exception skip the check?
   - Break a validation dependency (unreachable sub-service simulated by a malformed reference) —
     does the app reject, or default to "allow"?
   - Send input that throws *after* an access grant but *before* a revoke/commit — is the grant
     left in place?
   ```bash
   # example: role lookup that may throw on a bad id — does authz fail open?
   curl -s "https://target/api/admin/report" -H "Authorization: Bearer $LOWPRIV_TOKEN_WITH_BAD_ROLE_CLAIM"
   ```

4. **Toggle debug/verbose surfaces.** Probe common verbose triggers:
   ```bash
   for q in "?debug=1" "?trace=1" "?__debug__=true"; do curl -s "$EP$q" | head -c 300; echo; done
   curl -s $EP -H "X-Debug: true" | head -c 300
   # dev vhost / host-header swap sometimes flips verbose errors on
   curl -s $EP -H "Host: dev.target" | head -c 300
   ```

5. **Partial-failure / state-consistency.** In multi-step flows, interrupt mid-way (drop the
   connection, send a malformed final step, race a cancel) and check whether the system is left
   permissive or inconsistent (resource granted, limit not decremented, lock not released).

6. **Classify precisely.** For each result say which it is: *information leak* (what internals,
   actionable how) or *fail-open* (which check was skipped, what access/effect resulted). A bare
   `500` with no body and no behaviour change is neither — it's a stability bug, not a security
   finding.

## Tooling

- `radamsa` — fast structured-input mutation to generate malformed variants from a seed request.
- Burp Intruder / `ffuf` — drive the malformation matrix (types × fields × content-types) and
  diff responses at scale.
- `curl` — precise one-off malformed requests and grepping the error body for internals.
- A response-diff helper (length / status / key-substring) to separate happy-path, leak, and
  fail-open outcomes from the noise.

## Root Causes

- Verbose error handlers / debug mode enabled in production — unhandled exceptions rendered with
  full stack traces, framework details, or echoed internals (CWE-209).
- Missing or improper exception handling around security checks so a thrown exception bypasses the
  check instead of denying (CWE-755/CWE-636 "fail open") — e.g. `try { authorize() } catch {}`
  continuing, or a `null`/error treated as "no restriction".
- Validation written only for the happy path; unexpected types/shapes reach code that assumes the
  normal shape and either crashes (leak) or coerces into a permissive value.
- Non-atomic multi-step operations with no compensating rollback, leaving permissive partial state
  on mid-flow failure.
- Trusting a default-allow when a dependency (authz service, feature flag, entitlement store) is
  unavailable.

## Validation Gate (minimum proof)

- **Demonstrated:** a specific malformed/exceptional input produces a concrete security effect you
  show end to end — a verbose error leaking actionable internals (stack trace with
  framework+version / file paths / SQL / secret), OR a fail-open where the exceptional input
  causes a check to be skipped and you obtain access/data/effect you should not (show the request,
  the response, and the contrast with the properly-denied happy path).
- **Inferred:** the error path reveals *some* internal detail (an exception class/name, a generic
  framework banner) of limited actionability, or an endpoint behaves anomalously under
  malformation in a way that suggests fail-open but the security effect isn't yet pinned.
- **Unproven:** "it throws a 500" or "errors look verbose" with no actionable internal extracted
  and no check shown to be bypassed. Not a finding — a stability/robustness note at most.
- Separate the two sub-classes explicitly: **information leak** (recon/CVE value, usually
  lower-to-medium on its own) vs **fail-open** (an actual access/validation bypass, often high) —
  they have different impact and remediation.

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| Type confusion | string field → array/object/number/null | crash on type assumption or coerce permissively |
| Structural break | truncated JSON, missing/extra/dup keys | hit unhandled parse/validation paths |
| Content-type mismatch | `Content-Type: xml` with JSON body | confuse the parser/handler |
| Boundary values | `-1`, `0`, huge int, overflow, empty, huge string | edge-case math/validation errors |
| Encoding tricks | double-encode, bad UTF-8, null byte | break decoders → leak or bypass |
| Dependency-failure | malformed role/entitlement reference | force authz lookup to throw → fail-open? |
| Debug toggles | `?debug=1`, `X-Debug`, dev Host | flip verbose errors on |
| Partial flow | interrupt/malform a mid/last step | leave permissive partial state |

```bash
# Detection: malform each field and classify leak vs fail-open vs noise against the baseline.
EP="https://target/api/v2/order"; BASE='{"qty":1,"sku":"A1"}'
base_code=$(curl -s -o /tmp/ec.base -w "%{http_code}" -X POST $EP -H "Content-Type: application/json" -d "$BASE")
for mut in '{"qty":[1]}' '{"qty":null}' '{"qty":"x"}' '{"qty":1' '{}' '{"qty":1,"sku":{"a":1}}'; do
  code=$(curl -s -o /tmp/ec.out -w "%{http_code}" -X POST $EP -H "Content-Type: application/json" -d "$mut")
  leak=$(grep -ioE "Exception|Traceback|SQLSTATE|/var/|/home/|line [0-9]+|at [a-z0-9_.]+\(" /tmp/ec.out | head -1)
  echo "mut=$mut http=$code (base=$base_code) leak=${leak:-none}"
done
# A mutation returning 2xx where the baseline requires validation = fail-open candidate.
# A 500 body carrying stack/paths/SQL = information leak. A clean 400 = handled (safe).
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| input validation | malformed type the validator didn't model | reach code past the happy-path guard |
| authorization check | force the authz lookup to throw | if caught-and-continued, access is granted |
| rate/limit decrement | crash after action, before the decrement | permissive partial state |
| generic error page | trigger a different, unhandled exception type | one handler verbose, another not |
| prod "errors off" | dev vhost / debug header / stack param | verbose mode gated by a guessable toggle |
| commit/rollback | interrupt between grant and revoke | non-atomic flow leaves grant live |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Information leak → targeted exploit** — Framework/version from a stack trace → variant/CVE
   analysis (needs a real trigger to become its own finding); file paths → lfi-rfi; SQL fragment
   → sqli. Chain info-disclosure for the consolidated leak inventory.
2. **Fail-open → access** — Did the skipped check grant data/admin/cross-user access? Chain
   auth-bypass / broken-access-control.
3. **Fail-open → business-logic** — Permissive partial state (free resource, un-decremented
   limit, un-revoked grant) → quantify abuse (chain business-logic).
4. **Secret echo** — Did an error echo a token/key/connection string from config/env? Chain
   info-disclosure → credential-testing.
5. **DoS boundary** — A malformed input reliably crashing a worker may enable DoS; note it, but do
   not weaponize volume without an explicit gate.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Verbose error leak (stack/version/paths) → **info-disclosure** → variant-analysis / **lfi-rfi**
  / **sqli** leads.
- Fail-open on an authz check → **auth-bypass** / **broken-access-control** → protected data.
- Permissive partial state → **business-logic** abuse (resource/limit/grant inconsistency).
- Secret echoed in an error → **info-disclosure** → **credential-testing**.
- Malformed-input oracle differences can also sharpen **sqli**/**nosqli** error-based detection.

## Gotchas

- **A 500 is not automatically a finding.** An unhandled exception with no actionable leak and no
  behaviour change is a robustness bug, not a security one. The finding is *what leaks* or *what
  gets bypassed* — name it concretely.
- **Fail-open is the prize, leaks are the consolation.** A stack trace is useful recon but often
  medium/low alone; prioritise forcing security checks to throw and showing the check was skipped
  — that's the high-impact half of this class.
- **Don't fabricate impact from a version.** A framework version in a trace is a hypothesis for a
  CVE, not a finding — per anti-fabrication rules it needs a demonstrated trigger. Report the
  *leak*; keep the CVE as a lead unless you prove it.
- **Separate "errored" from "bypassed".** A permissive response under malformation might be the
  app correctly handling your input a different way — verify you actually obtained something you
  shouldn't (data/access/effect), not just a 200 on a weird request.
- **Mind stability and budget.** Fuzzing the error path can crash workers / trip alerts; respect
  the engine's limits, avoid volume that degrades the target, and don't repeat a crash more than
  needed to prove it.
- **Common N/A:** errors return generic sanitized messages (no internals) AND security checks
  deny on exception (fail-closed) — record tested-and-robust with the malformation set you tried.
