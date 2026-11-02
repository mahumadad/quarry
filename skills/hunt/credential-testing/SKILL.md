---
name: credential-testing
description: >-
  Test authentication strength: hash cracking feasibility, default credentials, password policy compliance, and credential spraying.
---

# Credential Testing

> Test authentication strength: hash cracking feasibility, default
> credentials, password policy compliance, and credential spraying.

## Prerequisites

- Scope confirmed (`/quarry:scope`) with credential testing authorized
- AppProfile available (tech stack, auth mechanisms identified)
- Account lockout policy documented or unknown (assume aggressive)

## Steps

### 1. Hash identification

If hashes are obtained (from DB dump, config leak, info-disclosure):

```
hashid '{hash_value}'
hashcat --identify '{hash_value}'
```

Common modes: MD5=0, SHA1=100, SHA256=1400, bcrypt=3200, NTLM=1000,
SHA512crypt=1800, PBKDF2-SHA256=10900, Argon2=argon2id.

**Policy check:** if hashes use MD5/SHA1/SHA256 without salt → finding
(weak hashing algorithm). If bcrypt cost < 10 or PBKDF2 iterations
< 600k → finding (insufficient work factor per NIST 800-63B §5.1.1.2).

### 2. Wordlist selection

| Context | Primary | Fallback |
|---------|---------|----------|
| General web app | `rockyou.txt` | `seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt` |
| Admin/service accounts | `seclists/Passwords/Default-Credentials/default-passwords.txt` | `seclists/Passwords/Leaked-Databases/` |
| Technology-specific | `seclists/Passwords/Default-Credentials/{product}-default-passwords.txt` | Custom per engagement |
| Targeted (client name) | Build from OSINT: company name + year + season + symbols | `hashcat rules: best64.rule, OneRuleToRuleThemAll.rule` |

### 3. Default credential testing

Check defaults for every detected technology:

| Technology | Default creds | Check endpoint |
|-----------|---------------|----------------|
| WordPress | admin:admin, admin:password | `/wp-login.php` |
| Tomcat | tomcat:tomcat, admin:admin | `/manager/html` |
| Jenkins | admin:admin (no auth if setup skipped) | `/login` |
| Grafana | admin:admin | `/login` |
| phpMyAdmin | root:(empty) | `/` |
| Elasticsearch | (no auth) | `:9200` |
| MongoDB | (no auth) | `:27017` |
| Redis | (no auth) | `:6379` |
| RabbitMQ | guest:guest | `:15672` |
| PostgreSQL | postgres:postgres | `:5432` |
| MySQL | root:(empty), root:root | `:3306` |
| Spring Boot Actuator | (no auth) | `/actuator` |
| Cisco | admin:admin, cisco:cisco | web UI / SSH |
| FortiGate | admin:(empty) | `:443` |

**Gate:** test max 5 attempts per account. Stop if lockout detected.

### 4. NIST 800-63B password policy audit

Verify these controls against the auth implementation:

| NIST 800-63B Requirement | Test |
|--------------------------|------|
| Min 8 chars (memorized), 6 (random) | Register with short passwords |
| Max ≥ 64 chars allowed | Register with 65+ char password |
| No composition rules required | Check if "Password1!" is rejected but "correct horse battery staple" accepted |
| Check against breach lists (HIBP) | Register with "Password1" — should be rejected |
| No periodic rotation forced | Check account settings for forced rotation |
| Rate limiting on auth attempts | Send 10 rapid login attempts |
| No SMS-only MFA | Check MFA options offered |
| Secure password storage (bcrypt/Argon2/PBKDF2) | From hash analysis in step 1 |

Each failure is a finding tagged to NIST 800-63B.

### 5. Credential spray planning

**Pre-checks before spraying:**

1. Identify lockout policy:
   - Try 3 wrong passwords → check for lockout message
   - Check response headers for `X-RateLimit-*`, `Retry-After`
   - Look for CAPTCHA triggers
2. Document: threshold (N attempts), window (M minutes), lockout duration

**Spray parameters:**

```
# Conservative: 1 password per account per lockout window
# Target list: harvested usernames from recon (email-harvesting, OSINT)
# Password: ONE common password at a time across ALL users

# Example with hydra (if authorized):
hydra -L users.txt -p 'Summer2026!' {target} http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid" \
  -t 1 -W 30
```

**Spray rules:**
- ONE password per round across all accounts
- Wait full lockout window between rounds
- Max 3-5 rounds per engagement unless client authorizes more
- Top spray passwords: `{Season}{Year}!`, `{Company}2026!`, `Welcome1!`, `Password1!`, `Changeme1!`
- **Human gate required** before each spray round

### 6. Document findings

For each credential issue found:

- **Weak hash algorithm:** evidence = hash sample (redacted), algorithm
  identified, NIST reference
- **Default credentials:** evidence = successful auth request/response,
  account accessed, data exposed
- **Policy violation:** evidence = what the policy allows vs NIST
  requirement, test requests proving the gap
- **Spray success:** evidence = successful auth request/response (redacted
  password after confirmation), account type, data accessible

## Chain Anchors

After credential access obtained:
1. Check for privilege escalation paths (mass-assignment, IDOR with new session)
2. Check for MFA bypass (alt auth flows, device trust)
3. Check for session management issues (concurrent sessions, no logout)
4. Check for horizontal movement (same password on other services)
5. Check for data access scope (what does this credential access?)

## Evidence

- All credential test requests/responses in custody log
- Hash samples with algorithm identification
- Lockout policy documentation
- Spray timing log (attempts per window)
- NIST 800-63B compliance matrix filled

## Never Submit

- Brute force without authorization
- Spray results without documenting lockout policy first
- "Weak password policy" without specific NIST 800-63B reference
- Default credential finding if the service is not reachable from the
  attack surface (internal-only behind VPN)
