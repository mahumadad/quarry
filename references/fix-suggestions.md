# Fix Suggestion Reference

> Remediation guidance by vulnerability class.
> These are suggestions, not auto-patches. Each fix must be adapted
> to the target's specific stack and architecture.

## Fix Patterns by Vuln Class

| Vuln Class | Fix Pattern | Example | Reference |
|---|---|---|---|
| sqli | Parameterized queries / prepared statements | `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` | OWASP SQL Injection Prevention |
| xss-reflected | Output encoding per context (HTML, JS, URL, CSS) | `escape(user_input)` in template | OWASP XSS Prevention |
| xss-stored | Input validation + output encoding + CSP | `Content-Security-Policy: script-src 'self'` | OWASP CSP Cheat Sheet |
| ssrf | Allowlist of permitted URLs/hosts, block internal ranges | Validate URL against allowlist before fetch | OWASP SSRF Prevention |
| idor | Authorization check on every resource access | `if resource.owner_id != current_user.id: return 403` | OWASP IDOR Prevention |
| csrf | Synchronizer token pattern or SameSite cookies | `SameSite=Strict` on session cookies | OWASP CSRF Prevention |
| rce | Avoid system() calls, use safe APIs, sandbox execution | `subprocess.run(["cmd", arg], shell=False)` | CWE-78 Mitigation |
| ssti | Use logic-less templates or sandbox template engine | Switch from Jinja2 `eval` to `SandboxedEnvironment` | PortSwigger SSTI |
| xxe | Disable external entity processing in XML parser | `parser.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` | OWASP XXE Prevention |
| lfi | Avoid user-controlled file paths, use allowlist | Map user input to fixed file IDs, not paths | CWE-22 Mitigation |
| file-upload | Validate content type + extension + magic bytes, store outside webroot | `file.content_type in ALLOWED_TYPES and magic_matches(file)` | OWASP File Upload |
| auth-bypass | Enforce auth on all endpoints, centralized middleware | Auth middleware applied globally, not per-route | OWASP AuthN Cheat Sheet |
| jwt | Use RS256+, validate all claims, rotate keys | `jwt.decode(token, public_key, algorithms=["RS256"])` | JWT Best Practices RFC 8725 |
| cors-misconfiguration | Explicit origin allowlist, never reflect Origin | `Access-Control-Allow-Origin: https://app.example.com` | OWASP CORS |
| open-redirect | Allowlist of permitted redirect targets | `if urlparse(redirect).netloc in ALLOWED_HOSTS` | CWE-601 Mitigation |
| deserialization | Avoid native deserialization of untrusted data | Use JSON instead of Java serialization/pickle | OWASP Deserialization |
| mass-assignment | Explicit allowlist of assignable fields | `User.objects.create(**{k: v for k, v in data.items() if k in ALLOWED})` | OWASP Mass Assignment |
| graphql-introspection | Disable introspection in production | `introspection: process.env.NODE_ENV !== 'production'` | GraphQL Security |
| race-condition | Database-level locking or atomic operations | `SELECT ... FOR UPDATE` or `SERIALIZABLE` isolation | CWE-362 Mitigation |
| api-key-leak | Rotate exposed keys immediately, use secrets manager | Store in Vault/AWS Secrets Manager, not code | OWASP Secrets Management |

## General Recommendations

### Defense in Depth

1. **Input validation** — reject invalid input at the boundary
2. **Output encoding** — encode output per context (HTML, JS, SQL, OS)
3. **Authentication** — verify identity on every request
4. **Authorization** — verify permissions on every resource
5. **Logging** — log security events for detection
6. **Rate limiting** — prevent brute-force and enumeration

### Headers

```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Usage in Reports

When including fix suggestions in a finding report:
1. Reference the specific pattern from this table
2. Adapt the code example to the target's stack
3. Include the OWASP/CWE reference for deeper guidance
4. Note: suggestions are guidance — the development team implements
