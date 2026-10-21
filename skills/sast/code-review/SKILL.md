---
name: sast-code-review
description: >
  Static analysis of source code for security vulnerabilities.
  Requires access to target source code (open source, leaked, or provided).
metadata:
  category: sast
  phase: [MAPPED, HUNTING]
  priority: P1
  depends_on: [research-first]
  feeds_into: [hunt/*]
  chains_with: [app-profile]
---

# SAST — Source Code Security Review

When source code is available (open-source target, code provided by client,
or code leaked/discovered during engagement), perform static analysis to
find vulnerabilities that black-box testing might miss.

## When to Use

- Target is open-source or has public repositories
- Client provided source code for grey/white-box testing
- Source code discovered during engagement (e.g., .git exposed, backup files)
- Supplement to black-box testing for better coverage

## Analysis Pipeline

### 1. Language & Framework Detection
```
Identify: language, framework, ORM, auth library, template engine
Check: package.json, requirements.txt, Gemfile, pom.xml, go.mod
Map to: known vulnerability patterns for that stack
```

### 2. Sink Analysis (dangerous functions)

#### SQL Injection Sinks
```
Python:  cursor.execute(f"..."), raw(), text(), execute()
Node.js: mysql.query(), pool.query(), knex.raw()
PHP:     mysql_query(), mysqli_query(), PDO::query()
Java:    Statement.execute(), createQuery()
Ruby:    where("...#{...}"), find_by_sql()
Go:      db.Query(fmt.Sprintf(...)), db.Exec()
```

#### Command Injection Sinks
```
Python:  os.system(), subprocess.call(shell=True), eval()
Node.js: child_process.exec(), eval(), Function()
PHP:     system(), exec(), passthru(), shell_exec(), eval()
Java:    Runtime.exec(), ProcessBuilder
Ruby:    system(), exec(), `backticks`, IO.popen()
```

#### XSS Sinks
```
React:   dangerouslySetInnerHTML, href={user_input}
Vue:     v-html
Angular: bypassSecurityTrust*, [innerHTML]
Django:  |safe, mark_safe(), {% autoescape off %}
Rails:   raw(), html_safe
Express: res.send(user_input) without encoding
```

#### SSRF Sinks
```
Python:  requests.get(user_url), urllib.urlopen()
Node.js: axios(user_url), fetch(user_url), http.get()
PHP:     file_get_contents(user_url), curl_exec()
Java:    URL(user_url).openConnection()
```

#### Deserialization Sinks
```
Python:  pickle.loads(), yaml.load() (without SafeLoader)
Node.js: node-serialize, js-yaml (without safe mode)
PHP:     unserialize()
Java:    ObjectInputStream.readObject(), XMLDecoder
.NET:    BinaryFormatter, XmlSerializer with type input
```

### 3. Source-to-Sink Tracing
```
For each sink:
  1. Trace back to the source (user input entry point)
  2. Map all transformations/sanitizations in between
  3. Check: is ANY path unsanitized?
  4. If yes → candidate finding
  5. Verify: can the unsanitized path be triggered externally?
```

### 4. Authentication & Authorization Review
```
Check:
  - Auth middleware applied consistently?
  - RBAC checks on every protected endpoint?
  - Password hashing algorithm (bcrypt/argon2 vs MD5/SHA1)
  - Session management (secure, httpOnly, sameSite)
  - JWT validation (alg check, expiration, signature)
  - API key validation and rotation
```

### 5. Configuration Review
```
Check:
  - Debug mode in production configs
  - Hardcoded secrets (API keys, passwords, tokens)
  - CORS configuration
  - CSP headers
  - Database connection strings
  - Cloud credentials in code
```

## Output Format

Each finding from SAST should include:
- File path and line number
- Vulnerable code snippet
- Sink function and source (user input)
- Sanitization gaps identified
- PoC or exploitation path (if determinable statically)
- Confidence: HIGH (clear path) / MEDIUM (likely) / LOW (needs dynamic confirm)

## SAST Agent Pipeline (for large codebases)

For repositories with 50+ files of security-relevant code, use the full
SAST agent pipeline instead of manual analysis:

1. `sast-file-ranker` (haiku) — ranks files by security relevance (0-100)
2. `sast-entry-mapper` (haiku) — maps all entry points with auth context
3. `sast-sink-finder` (sonnet) — finds dangerous sinks per vuln class
4. `sast-flow-tracer` (opus) — traces source → sanitization → sink paths
5. `sast-gap-analyzer` (sonnet) — identifies coverage gaps
6. `sast-devils-advocate` (sonnet) — adversarial review of all findings

The pipeline uses stable IDs (EP-nnn, SINK-nnn, TRACE-nnn, GAP-nnn) to
link stages. Flow-tracer findings are capped at `Inferred` confidence
since static analysis cannot `Demonstrate` — dynamic verification is
required for HIGH confidence findings.

## Gotchas

- SAST findings at LOW confidence MUST be verified dynamically before reporting
- Don't report safe patterns as vulnerabilities (parameterized queries, etc.)
- Framework-provided sanitization usually works — verify the bypass, not the pattern
- Dead code and test code are not findings
- Check if the vulnerable code is reachable from an external entry point
