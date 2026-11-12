# Gotchas: SQL Injection

## Common False Positives
- Generic HTTP 500 after adding `'` or `"`: any unhandled exception (type conversion, validation, null deref) produces a 500. Without a DB-specific error string it is not SQLi.
- Time delay from `SLEEP()`/`pg_sleep()`/`WAITFOR` that is not repeatable: network jitter, WAF tarpit, cold cache or rate limiting. A single slow response proves nothing.
- Boolean difference that is really input validation: `1 AND 1=1` vs `1 AND 1=2` differ because a WAF/validator rejects the second, not because the query evaluated it.
- WAF/CDN block page (403, Cloudflare 1020, ModSecurity) triggered by `UNION SELECT` or `OR 1=1`: the payload never reached the app.
- Numeric field "arithmetic injection" (`id=2-1` returns record 1): can be the framework casting/evaluating the expression, or the app computing it in code, not in SQL. Confirm with a string-concat or DB-specific function.
- Error messages quoting your payload from an ORM/validation layer (e.g. "invalid value `'`"): input echoed by the app, no SQL parsed.
- NoSQL-style operators (`$ne`, `$gt`) succeeding on a JSON endpoint reported as SQLi: it is NoSQL injection, a different class with different proof.
- sqlmap "possible injection" or `--technique=T` hits on high-latency targets: sqlmap heuristics produce false positives on unstable hosts; re-verify manually.
- Stored data that contains SQL keywords (a user named `O'Brien`, `DROP TABLE`) rendering fine: proves proper parameterization, not a flaw.

## Overclaim Traps
- "Critical RCE via SQLi" when only `SELECT` was proven: stacked queries, `xp_cmdshell`, `COPY ... PROGRAM`, `INTO OUTFILE` each need their own proof (privilege + working primitive).
- "Full database compromise" from a read of one table or `@@version`: scope the claim to what was actually extracted.
- Rating SQLi as Critical when the vulnerable endpoint requires admin auth or an internal-only network: adjust PR/AV in CVSS honestly.
- Blind SQLi with only one extracted character: say "confirmed injection point, extraction limited", not "data exfiltration".
- Claiming the DB user is DBA/`sa` from a version banner: privilege must be shown (`current_user`, `IS_SRVROLEMEMBER`, `pg_roles`).
- Reporting every parameter of the same vulnerable query as separate findings: one root cause, one finding.
- Scanner output with "SQL injection" tagged on a static or non-DB endpoint: scanners match error-ish strings in unrelated content.

## Minimum Proof Required
- Exact request (method, URL, parameter, payload, auth context) and the full relevant response.
- One of: (a) DB-specific error text produced by your payload (e.g. `You have an error in your SQL syntax`, `ORA-00933`, `unterminated quoted string`), (b) data extracted that you should not otherwise see, or (c) a boolean/time oracle reproduced at least 3 times with a matching control request.
- A control: baseline request and a "neutralized" payload (e.g. `'` vs `''`) behaving differently and predictably.
- For extraction claims: a harmless, verifiable value (DB version, current database name, row count), not bulk data. Do not dump real PII.
- For privilege/RCE claims: separate proof of the privilege and primitive, with operator approval before any state-changing payload.
- Database engine identified and how (error, function behaviour, comment syntax).

## When to Mark N/A
- The parameter is demonstrably bound via prepared statements and special characters are stored/handled literally with no behavioural change.
- The endpoint has no database interaction (static content, proxied third-party API) confirmed by behaviour or source.
- Only NoSQL/GraphQL/LDAP backends: reclassify to the correct injection class, not N/A for injection overall.
- Target is outside the engagement scope or the testing was blocked by WAF and no bypass was in scope: mark "Not tested / blocked", not "Not vulnerable".
