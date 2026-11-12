# Session Management Vulnerabilities

## What it is

Weaknesses in how the application creates, maintains, and destroys user
sessions. Covers session fixation, insufficient entropy, missing
invalidation, concurrent sessions, and cookie misconfigurations.

**CWE**: CWE-384 (Session Fixation), CWE-613 (Insufficient Session
Expiration), CWE-330 (Insufficient Randomness), CWE-539 (Persistent Cookies)

## Common patterns

### Session fixation
- Application accepts externally-set session ID (via URL, hidden field, cookie)
  and does not regenerate it after authentication
- Attacker sets session ID → victim authenticates with that ID → attacker
  uses same ID as authenticated session

### Insufficient entropy
- Session tokens short or predictable (sequential, timestamp-based, MD5 of
  user ID)
- Session token visible in URL (query string) → leaked via Referer, logs,
  browser history

### Missing invalidation
- Logout does not destroy server-side session (cookie cleared but session valid)
- Password change does not invalidate other active sessions
- Session tokens never expire (or expire after days/weeks)
- No idle timeout on sensitive applications

### Concurrent session issues
- No limit on concurrent sessions → compromised credentials yield persistent
  access even after password change
- No "log out all sessions" capability

## Exploitation

```bash
# Session fixation test
# 1. Get a session before login
SESSION=$(curl -sI "$TARGET/login" | grep -i "set-cookie" | grep -oP 'session=\K[^;]+')
echo "Pre-auth session: $SESSION"

# 2. Authenticate with that session
curl -s -b "session=$SESSION" -X POST "$TARGET/login" \
  -d "user=testuser&pass=testpass" -D - | grep -i "set-cookie"
# If no new Set-Cookie → session not regenerated → fixation possible

# 3. Check if pre-auth token still works post-auth
curl -s -b "session=$SESSION" "$TARGET/dashboard"

# Session invalidation test
# 1. Login, capture token
TOKEN=$(curl -sI -X POST "$TARGET/login" -d "user=test&pass=test" \
  | grep -i "set-cookie" | grep -oP 'session=\K[^;]+')

# 2. Logout
curl -s -b "session=$TOKEN" "$TARGET/logout"

# 3. Reuse token — should fail
curl -s -b "session=$TOKEN" "$TARGET/dashboard"
# If still authenticated → session not invalidated server-side

# Session token entropy
# Collect multiple tokens and check randomness
for i in $(seq 1 20); do
  curl -sI "$TARGET/" | grep -oP 'session=\K[^;]+' >> tokens.txt
done
# Check for patterns: sequential, timestamp-based, short length
sort tokens.txt | uniq -c | sort -rn | head
wc -c < <(head -1 tokens.txt)  # length check

# Cookie flags
curl -sI "$TARGET/login" -X POST -d "user=test&pass=test" | grep -i "set-cookie"
# Check: Secure, HttpOnly, SameSite, Path, Domain, Expires/Max-Age
```

## Evidence requirements

- **Session fixation**: pre-auth session ID works as authenticated session
  after victim logs in with that ID (show both requests)
- **Missing invalidation**: post-logout token still returns authenticated content
- **Insufficient entropy**: statistical analysis of collected tokens showing
  predictable patterns or low bits of randomness
- **Concurrent sessions**: demonstrate that a password change does not kill
  existing sessions

## Severity

| Variant | Severity | Condition |
|---|---|---|
| Session fixation | High | Attacker can set session ID for victim |
| Logout doesn't invalidate server session | Medium | Token reuse after logout |
| Password change doesn't kill other sessions | Medium | Persistent access |
| Session in URL (query string) | Medium | Leaked via Referer/logs |
| Missing Secure flag on session cookie | Medium | HTTPS available |
| Missing HttpOnly on session cookie | Medium | XSS → session theft |
| No session timeout (no idle/absolute) | Low-Medium | Depends on app sensitivity |
| Predictable session tokens | Critical | If enumerable → mass hijack |
| No concurrent session limit | Low | Informational for most apps |

## Chains

- Session fixation → account takeover (attacker pre-sets session → victim logs in)
- XSS + missing HttpOnly → session theft
- Missing Secure flag + network MITM → session hijack
- Missing invalidation on password change + credential stuffing → persistent access
- Session in URL + open redirect → token leaked to attacker via Referer
