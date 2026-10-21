---
name: hunt-crlf-injection
description: >
  Hunt for CRLF injection: HTTP response header injection, HTTP response
  splitting, log injection/forging, and SMTP/log line injection via
  unsanitized CR/LF in user input reflected into headers, redirects, or
  log sinks. Use when a parameter is reflected into a Location/Set-Cookie
  header, a redirect target, or written to application logs. Keywords:
  CRLF, %0d%0a, response splitting, header injection, log injection,
  log forging.
  Do NOT use for SMTP header injection specifically in email-sending flows
  — use hunt-email-injection. Do NOT use for cache poisoning that results
  from the injected header — note it but cross-reference hunt-cache-poisoning.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-93, CWE-113, CWE-117]
  mitre_attack: [T1190, T1562.002]
  tools: [burpsuite, curl, ffuf]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-cache-poisoning, hunt-clickjacking, hunt-email-injection]
---

## Signals

- Any parameter reflected in a `Location:` header (redirects), `Set-Cookie:`, or custom response headers (`X-...`).
- URL-based redirect params: `?next=`, `?redirect=`, `?return_to=`, `?url=`.
- User-controlled values written verbatim to application/access logs (username field, User-Agent, custom headers echoed into logs).
- Backend frameworks with known historical CRLF issues in redirect helpers (older Java `sendRedirect`, Python frameworks before header validation was added, Go `net/http` before 1.18 header validation).

## Prerequisites

- Ability to observe raw response headers (curl -i or Burp) — browsers normalize/hide this, so a browser-only test will give false negatives.
- For log injection: some way to view the resulting log output (often requires LFI/another vuln, or is only provable via blind log-based detection — treat as Inferred unless log access is in scope).

## Methodology

1. **Identify reflection points.** Map every parameter that ends up in a response header. Check redirect endpoints first:
   ```bash
   curl -s -i "https://target.com/redirect?next=/dashboard"
   ```

2. **Basic CRLF probe into a redirect param.**
   ```bash
   curl -s -i "https://target.com/redirect?next=/dashboard%0d%0aX-Injected:%201"
   curl -s -i "https://target.com/redirect?next=/dashboard%0D%0AX-Injected:%201"
   # double-encoded in case of a decode-then-validate-then-decode-again flaw
   curl -s -i "https://target.com/redirect?next=/dashboard%250d%250aX-Injected:%201"
   # raw CR/LF unicode variants some parsers still accept
   curl -s -i "https://target.com/redirect?next=/dashboard%0aX-Injected:%201"
   curl -s -i "https://target.com/redirect?next=/dashboard%E5%98%8D%E5%98%8AX-Injected:%201"   # UTF-8 overlong CRLF trick on some stacks
   ```
   Success = `X-Injected: 1` appears as a genuine new header in the raw response, not inside the body.

3. **Response splitting — inject a full second response.** If a single CRLF works, try injecting a blank line (two CRLFs) to split the response and smuggle an attacker-controlled body/second response, which can enable reflected XSS even with output-encoding on the body elsewhere:
   ```bash
   curl -s -i "https://target.com/redirect?next=/dashboard%0d%0a%0d%0a<script>alert(1)</script>"
   ```

4. **Set-Cookie injection.** If the reflection point is in a cookie-setting flow, try injecting additional cookies or attributes:
   ```bash
   curl -s -i "https://target.com/setlang?lang=en%0d%0aSet-Cookie:%20admin=true"
   ```

5. **Open-redirect + CRLF combo.** If `next=` is validated to start with `/` but not for CRLF, this still enables header injection even if it doesn't enable off-site redirect — test both independently (see also hunt-host-header for redirect-target abuse).

6. **Log injection probe.** Send a payload with embedded CRLF plus a fake log line into any field that's likely logged (username on failed login, User-Agent, X-Forwarded-For):
   ```bash
   curl -s -i "https://target.com/login" -d "username=admin%0d%0a[INFO]%20User%20admin%20authenticated%20successfully&password=wrong"
   curl -s -i "https://target.com/" -H $'User-Agent: normal-agent\r\n[ALERT] fake log line injected'
   ```
   Confirm impact only if you have authorized access to view the resulting log file/SIEM and can show the forged line landed intact (two real log lines where one was expected) — otherwise label Unproven/Inferred.

7. **Verb/path-based injection points.** Some frameworks reflect the request path or method into error/debug headers — test malformed paths too:
   ```bash
   curl -s -i "https://target.com/%0d%0aX-Injected:%201/"
   ```

## Tooling

- `curl -i` (raw header visibility — essential, do not rely on a browser).
- Burp Repeater (raw response view, bypasses browser normalization).
- `ffuf` with a small CRLF-variant wordlist against every known redirect/reflection parameter at scale:
  ```bash
  ffuf -u "https://target.com/redirect?next=FUZZ" -w crlf_payloads.txt -mc all -fr "Location: /dashboard$"
  ```

## Root Causes

- User input concatenated directly into a raw header string before being written to the response, without stripping/rejecting CR (`\r`, `%0d`) and LF (`\n`, `%0a`).
- Framework-level redirect/cookie helpers that predate strict header-value validation, or custom header-setting code that bypasses the framework's safe helper.
- Logging code using string formatting/concatenation of user input directly into a log line template instead of structured logging (fields, not free text).

## Validation Gate (minimum proof)

- Raw HTTP response (headers verbatim, via `curl -i` or Burp raw view) showing the injected header actually parsed as a distinct header by the server, not merely present somewhere in the body/URL.
- For response splitting into XSS: a screenshot/log showing the injected script executing in a real browser context, since not all CRLF injections achieve body-splitting the same way across servers.
- For log injection: side-by-side of the forged multi-line log entry as it appears in the actual log store — only with explicit access scoped to view it; otherwise mark as Inferred from the blind payload alone.

## Gotchas

- **Minimum proof:** payload appearing echoed in the *body* (HTML-escaped or not) is not CRLF injection — it must be parsed as a structurally distinct HTTP header or log line.
- **Common N/A:** modern frameworks (recent Spring, Django, Express, Go ≥1.18, most current language HTTP libraries) reject raw CR/LF in header values at the standard library level — a 400 or stripped payload here is a clean N/A, don't force a finding.
- **Overclaim trap:** URL-encoded `%0d%0a` that the server decodes into the *path* but never reflects into a response header is not a finding on its own — confirm the exact sink.
- Double-encoding and Unicode "overlong" CRLF tricks only work on specific legacy/misconfigured decoders — test the straightforward payload first, don't jump to exotic encodings as the first move.
- Browser-rendered testing will hide real injected headers from you (browsers strip/normalize) — always verify with curl/Burp raw view before concluding N/A.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Response splitting** — Can injected CRLF split the HTTP response into two, enabling response smuggling to the client?
2. **Cache poisoning chain** — Can the injected headers poison a shared cache (chain with cache-poisoning)?
3. **Session fixation via Set-Cookie injection** — Can you inject an attacker-controlled Set-Cookie header to fixate another user's session?
4. **Log injection** — Does the CRLF reach application/server logs, enabling log forgery or log-based injection into a log viewer?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- CRLF into `Location` header + response splitting → reflected XSS even on sites with otherwise solid output encoding on the body.
- CRLF into cache-relevant headers → feeds hunt-cache-poisoning if the injected header affects a cached response.
- CRLF into `Set-Cookie` → session fixation/injection, chain with hunt-session-management.
- CRLF in SMTP headers of an email-composition flow → full takeover by hunt-email-injection, treat as the dedicated deep-dive for that sink.
- Log injection enabling log forging → can mask or fabricate audit trail entries, relevant to incident-response credibility findings.
