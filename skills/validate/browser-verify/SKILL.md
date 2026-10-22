---
name: browser-verify
description: >
  Runtime verification of client-side findings in a real browser engine (Playwright/Chromium).
  Use whenever a finding's impact lives in the browser — DOM/reflected/stored XSS, clickjacking,
  client-side open redirects — and the only evidence so far is HTTP traffic or static bundle
  analysis (`Inferred`). A client-side finding is only `Demonstrated` when an observable effect
  fired at runtime (dialog, DOM marker, frame load); code reading never counts. Run after
  evidence-hygiene and before finding-validation, so the four gates see runtime-grade evidence.
metadata:
  type: validate
  phase: validating
  tools: [engine/browser_verify.py, playwright]
depends_on: [evidence-hygiene]
feeds_into: [finding-validation]
---

## Signals

- A candidate XSS (DOM, reflected, or stored) was identified by static analysis of the JS
  bundle, a suspicious sink (`innerHTML`, `bypassSecurityTrust*`, `document.write`), or a
  reflected parameter — but nothing has executed in a browser yet.
- A clickjacking candidate: page without `X-Frame-Options` / `frame-ancestors` on paper,
  but no actual framing test was run (headers can be injected by a middlebox — trust the render).
- An OAST blind-XSS callback arrived (`engine/oast.py`) and you want the in-browser effect
  captured as visual evidence for the report.

## Prerequisites

- Playwright installed: `python3 -m pip install playwright && python3 -m playwright install chromium`.
  `engine/browser_verify.py` fails closed with these instructions if missing — never mark a
  finding Demonstrated because the probe errored.
- Scope allows active client-side testing (default for web engagements; confirm for targets
  with third-party SSO flows you might trigger).
- For stored XSS: the payload is already planted (via API/registration/import) and you hold a
  viewer-level session that renders the sink page (e.g. admin panel).

## Method

### 1. Reflected / DOM XSS

Place the payload in the URL exactly as a victim would receive it and load it headless:

```bash
python3 -m engine.browser_verify reflected-xss \
  "https://target/#/search?q=<PAYLOAD>" --out-dir evidence/
```

- Success signal: a `dialog:*` effect (alert/confirm fired by the canary) — definitive, cannot
  be produced by anything but script execution.
- `demonstrated: false` with a clean run = lead stays `Inferred`; report the sink, not the vuln.
- Save the JSON result + screenshot (SHA-256 included) as finding evidence.

### 2. Stored XSS

Plant a payload whose canary fires on render, then open the viewer page authenticated:

```bash
python3 -m engine.browser_verify stored-xss "https://target/#/administration" \
  --marker xssprobe7f3a --token "$VIEWER_JWT" --out-dir evidence/
```

- The token is injected into localStorage/sessionStorage before page scripts run (standard SPA
  bearer pattern). If the app uses cookies, attach them via a short Playwright script instead.
- Wait budget: admin panels render async — the probe already waits post-`networkidle`.
- One marker per attempt; reuse of markers across findings breaks correlation (same rule as OAST).

### 3. Clickjacking

```bash
python3 -m engine.browser_verify clickjacking "https://target/account" --out-dir evidence/
```

Demonstrated only when the page actually loads inside a foreign-origin iframe AND no
`frame-ancestors`/`X-Frame-Options` was sent. Header-present-but-rendered still counts as
vulnerable — the render is the ground truth.

## Anti-fabrication rules

- `Inferred` (static analysis, WAF-blocked attempts) findings never become `validated` through
  this skill unless a probe returns `demonstrated: true`.
- A probe that errors (timeout, crash, missing binary) is **no result**, not a negative result:
  record it as unproven and say the verification is pending.
- Screenshot evidence must carry its SHA-256 (the module does this) and enters the custody log
  like any other artifact.

## Common pitfalls

- **Payload eaten by the framework's sanitizer**: try the encoding/context variants from
  `references/payloads/` before declaring the sink safe — one bypass is enough for Demonstrated.
- **Angular/Vue hash routes**: pass the full URL including `#/…`; the router runs client-side.
- **`javascript:` URIs in modern Chromium** may require user activation; prefer
  `<img src=x onerror=…>` or `<svg onload=…>` vectors for reliability.
- **Headless detection**: some apps behave differently headless. If a Demonstrated effect
  matters for the report, note `headless: true` in the evidence metadata.
