---
name: chain-xss-to-account-takeover
description: >
  Analyze and validate XSS escalation chains: stored XSS to session/token
  theft, XSS combined with CSRF to perform privileged actions as the
  victim, and XSS used as an in-browser keylogger/credential harvester.
  Use when chain-analysis pairs a confirmed stored or persistent reflected
  XSS with identity-map's session/token mechanics.
  Do NOT use for self-XSS or XSS requiring implausible victim interaction
  not matching the engagement's defined threat actor — report those as
  standalone low-severity findings instead, see Gotchas.
metadata:
  type: chain
  phase: chaining
  tools: [burp, beef_xss_if_authorized, curl, mitmproxy]
depends_on: [chain-analysis, identity-map]
feeds_into: [chain-auth-to-takeover, finding-validation, report-writing]
chains_with: [chain-auth-to-takeover]
---

## Signals

- A stored or persistent XSS is confirmed on a page viewed by other users (not just the
  attacker's own session) — this is the precondition for every pattern in this skill.
- identity-map shows session tokens are reachable from JS (non-`HttpOnly` cookie, or token
  kept in `localStorage`/`sessionStorage`).
- A privileged action exists behind CSRF protection that the XSS could bypass by acting as
  the victim's browser directly rather than forging a cross-origin request.

## Prerequisites

- The XSS finding itself confirmed with a working injection point and payload context
  (HTML, attribute, JS string, URL) already identified.
- Explicit scope/authorization for testing against other real users' sessions vs. only
  test/sacrificial accounts — default to test accounts unless the client has explicitly
  scoped live-user impact testing.

## Methodology

1. **Stored XSS → session/token theft.**
   - Confirm where the session credential lives (identity-map output). If it's an
     `HttpOnly` cookie, direct JS theft of the cookie value is not possible — the chain
     instead needs to ride the victim's browser directly (see step 2) rather than exfiltrate
     the cookie string itself.
   - If the token is JS-reachable (non-`HttpOnly` cookie, `localStorage`/`sessionStorage`,
     or an `Authorization` header value cached in JS state), demonstrate exfiltration to an
     attacker-controlled listener using a test/sacrificial account's session, then
     demonstrate that the exfiltrated token is independently replayable from a separate
     client.

2. **XSS + CSRF (act-as-victim).**
   - For privileged actions protected by a CSRF token the attacker cannot forge cross-origin,
     demonstrate that the XSS payload, running same-origin in the victim's browser, can read
     the current page's CSRF token (from the DOM, a meta tag, or an in-page JS variable) and
     use it to submit the privileged action request directly.
   - This proves the CSRF protection is irrelevant once XSS exists on the same origin — note
     this precisely in the writeup: it's not that CSRF protection failed on its own terms,
     it's that same-origin XSS inherently bypasses it. Keep the two findings' severities
     distinct accordingly (see report/gotchas: CSRF).

3. **XSS as keylogger/credential harvester.**
   - Only pursue this pattern with explicit operator authorization given its direct-victim-
     impact nature. Build a minimal in-browser listener (not a full offensive framework
     deployment against real users) that demonstrates capture of form input on the affected
     page, tested against a test account filling a test form — never capture real user
     credentials in a demonstration.
   - The PoC artifact itself (keylogger payload) must be stored/handled per the engagement's
     evidence-handling rules; do not leave a live listener running past the demonstration
     window.

## Validation gate

- Every takeover claim requires a closed loop: payload delivered → effect observed on a
  controlled victim session → (if applicable) replay from an independent client confirming
  the stolen credential/token actually works.
- `HttpOnly`-protected tokens are explicitly noted as not directly exfiltratable — the chain
  write-up states which path was used (direct theft vs act-as-victim) accurately; don't
  blur the two.
- Keylogger/credential-harvesting PoCs are scoped to test accounts and test data only,
  explicitly authorized, and time-boxed — no live listener survives past the demonstration.

## Gotchas

- A `Content-Security-Policy` that blocks inline scripts or restricts `connect-src` can
  block the exfiltration channel even though the injection itself succeeds — test the actual
  exfil path, don't assume it works because the injection landed.
- `SameSite=Strict/Lax` cookies reduce classic CSRF risk but do nothing against same-origin
  XSS riding the victim's session directly — don't let a strong `SameSite` setting lead to
  under-claiming the XSS+CSRF chain's real impact.
- Self-XSS (requires the victim to paste something into their own console/URL bar) does not
  meet Gate 3 (can an unprivileged *attacker* trigger this against a victim) for most threat
  models — report it, if at all, as a standalone minor finding, not as the basis for a
  takeover chain.
- Short-lived session tokens reduce the exploitation window — note token lifetime in the
  writeup since it affects real-world severity, not just the demo's timing.
- Testing against a real logged-in user's session without separate explicit authorization is
  out of bounds regardless of how confident the XSS is — stick to test accounts.
