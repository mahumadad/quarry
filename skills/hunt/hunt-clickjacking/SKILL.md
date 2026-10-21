---
name: hunt-clickjacking
description: >
  Hunt for clickjacking: missing/misconfigured X-Frame-Options and CSP
  frame-ancestors allowing the page to be framed, plus drag-and-drop and
  double-click-jacking variants that bypass framebusting scripts. Use on
  any sensitive state-changing page (account settings, payment, consent,
  password change) reachable while authenticated. Keywords: clickjacking,
  X-Frame-Options, frame-ancestors, CSP, framebusting, UI redressing,
  drag-and-drop jacking.
  Do NOT use for CSRF that doesn't rely on framing/visual deception — that
  is a separate access-control issue, note it but this skill is specifically
  about the framing vector.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-1021]
  mitre_attack: [T1204.001, T1185]
  tools: [burpsuite, curl]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-subdomain-takeover, hunt-session-management, hunt-oauth]
---

## Signals

- No `X-Frame-Options` header and no `Content-Security-Policy: frame-ancestors` on sensitive pages.
- A `X-Frame-Options: ALLOW-FROM` directive (deprecated, ignored by modern browsers — effectively no protection).
- A framebusting JS snippet (`if (top !== self) top.location = self.location;`) as the *only* defense — these are routinely bypassable.
- Sensitive one-click actions: "Delete account", "Confirm payment", "Enable 2FA", "Change email", OAuth consent "Allow" buttons.

## Prerequisites

- A page you control to host the iframe PoC (local HTML file is enough for the PoC itself).
- A real account on the target to verify the action actually executes when framed (not just that the frame loads).

## Methodology

1. **Check headers directly.**
   ```bash
   curl -s -I https://target.com/account/settings | grep -i -E 'x-frame-options|content-security-policy'
   ```
   Interpret results:
   - No `X-Frame-Options` AND no `frame-ancestors` in CSP → likely framable, proceed to PoC.
   - `X-Frame-Options: DENY` or `SAMEORIGIN`, or CSP `frame-ancestors 'self'`/`frame-ancestors 'none'` → properly protected, test anyway for scope gaps (see step 4).
   - `X-Frame-Options: ALLOW-FROM https://partner.com` → test whether that allow-listed origin is actually trustworthy/necessary, and confirm modern browsers ignore this directive entirely (meaning the page may be unprotected in practice despite the header's intent).

2. **Build the minimal PoC.**
   ```html
   <!DOCTYPE html>
   <html>
   <head><title>Clickjack PoC</title></head>
   <body>
     <h1>Totally legit page</h1>
     <div style="position:relative;width:500px;height:500px;">
       <iframe src="https://target.com/account/delete"
               style="position:absolute;top:0;left:0;width:500px;height:500px;opacity:0.0001;z-index:2;"></iframe>
       <button style="position:absolute;top:250px;left:200px;z-index:1;">Click here to win a prize</button>
     </div>
   </body>
   </html>
   ```
   Open with the target account logged in (same browser session) and confirm the iframe actually loads (no breakout) via DevTools.

3. **Align the bait button with the real target button.** Use browser DevTools on the real page to get exact pixel coordinates of the sensitive button, then position the decoy button/iframe so a real click lands on the hidden target element. Confirm with a live click (on your own test account) that the sensitive action actually fires — a frame that merely loads without the click landing correctly is not yet a finding.

4. **Framebusting bypass, if a JS-only defense is present.**
   - **Double framing**: nest the target in two iframes; some old busting scripts check `top.location` assuming only one level and fail (`frame-in-frame`).
   - **`sandbox` attribute abuse**: `<iframe sandbox="allow-forms allow-scripts" src="...">` — the `sandbox` attribute disables top-navigation from inside the frame, neutralizing `top.location=` busting scripts entirely while still allowing the page to render and be clicked:
     ```html
     <iframe src="https://target.com/account/delete" sandbox="allow-forms allow-scripts allow-same-origin" style="opacity:0.0001;position:absolute;top:0;left:0;"></iframe>
     ```
   - **`Content-Security-Policy` self-conflict**: if the busting relies on `window.open`/`onbeforeunload`, test disabling popups/JS execution context tricks via sandbox flags.

5. **Drag-and-drop / scroll jacking variant.** For actions requiring drag (file upload areas, slider confirmations) or a sequence of clicks, chain multiple invisible iframes at different z-index/positions so a natural user drag/scroll path crosses several hidden targets in the needed order.

6. **Cross-origin resource/consent pages.** Specifically test OAuth consent screens and payment iframes (often embedded by third parties legitimately) — if `frame-ancestors` is missing there, the "Allow"/"Pay" button itself becomes jackable (chain with hunt-oauth).

## Tooling

- `curl -I` for fast header triage across many URLs:
  ```bash
  for url in $(cat urls.txt); do echo "== $url =="; curl -s -I "$url" | grep -i -E 'x-frame-options|frame-ancestors'; done
  ```
- Burp Suite's built-in **Clickjacking PoC generator** (right-click a response > "Engagement tools" > "Generate CSRF PoC" has a clickjacking variant, or use the manual template above).
- Browser DevTools for coordinate alignment and verifying the click actually reaches the framed element (not blocked by `pointer-events` or frame breakout).

## Root Causes

- `X-Frame-Options` header absent entirely (modern browsers no longer universally require it if CSP is present, but many apps have neither).
- `Content-Security-Policy` present for other directives (script-src, etc.) but missing `frame-ancestors`.
- Reliance on client-side framebusting JavaScript instead of a server-sent, browser-enforced header — JS defenses can be disabled via `sandbox`, disabling JS in the iframe (if the sensitive action doesn't require JS to execute), or double-framing.

## Validation Gate (minimum proof)

- Screen recording or sequential screenshots showing: (1) the decoy page with the invisible/disguised iframe, (2) the click landing on the real target element, (3) the sensitive action's effect actually taking place on the real test account (e.g. the account setting changed, confirmed via a follow-up authenticated request).
- Just "the page loads in an iframe" is not sufficient — you must prove the click reaches and triggers the sensitive action.
- Include the exact response headers captured at time of testing (headers can change per route/environment).

## Gotchas

- **Minimum proof:** a framable page that has no state-changing single-click action on it (e.g. a read-only dashboard) is a missing-header hardening note, not a clickjacking finding — severity requires a real sensitive action.
- **Common N/A:** `frame-ancestors 'none'` or `'self'` correctly set and enforced (verify in an actual browser, not just by reading the header — some proxies strip CSP) — close as N/A.
- **Overclaim trap:** reporting "missing X-Frame-Options" site-wide as critical when the only framable pages are static marketing content with no sensitive actions — scope severity to what's actually exploitable.
- GET-based state-changing actions (delete via a link, not a form) are easiest to clickjack — but if the same action already requires a CSRF token validated server-side, framing alone won't bypass that; check both together.
- Test on the real rendering engine your scope implies (desktop vs mobile browsers can differ in frame/sandbox enforcement).

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Sensitive action framed** — Does the vulnerable page perform a sensitive, state-changing action (not just a passive view) when framed?
2. **X-Frame-Options/CSP gap scope** — Is the missing frame protection site-wide or limited to one page/route?
3. **Working UI-redress PoC** — Can you build a working click-jack PoC that drags a real user interaction, not just a theoretical overlay, to the hidden action?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Clickjacking a settings page with no CSRF token → full account takeover by itself (no CSRF bypass needed since the real session cookie rides along).
- Clickjacking OAuth consent screen → forces scope/permission grant, chain with hunt-oauth.
- Clickjacking atop a takeover'd subdomain used as the "legit-looking" outer page → increases attack credibility, chain with hunt-subdomain-takeover.
- Clickjacking a "log out all other sessions: cancel" button to force a session to persist → tangential chain with hunt-session-management.
