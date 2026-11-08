---
name: js-analysis
description: >
  Extract hidden endpoints, API paths, and secrets (API keys, tokens, internal URLs) from
  JavaScript files using linkfinder and secretfinder-style regex analysis. Use after
  web-crawling has produced a list of JS file URLs, to mine them for attack surface that
  isn't visible in the rendered HTML. Do NOT use for live API testing — that's api-discovery;
  this skill only extracts candidates from static JS source.
metadata:
  type: recon
  phase: mapped
  tools: [linkfinder, secretfinder, trufflehog, curl, jsluice]
depends_on: [tech-stack-fingerprint, web-crawling]
feeds_into: [api-discovery, github-dorking]
---

## Signals

- JS file list exists from `web-crawling` and hasn't been mined for endpoints/secrets yet.
- Suspect hardcoded API keys, internal hostnames, or undocumented endpoints in bundled JS.
- An SPA's real API surface isn't visible from HTML crawling alone.

## Prerequisites

- List of JS file URLs from `web-crawling` (`static-assets.txt` filtered to `.js`).

## Methodology

1. Download all JS files locally for offline analysis (reduces repeat requests to the target,
   consistent with `opsec-discipline`):
   ```bash
   grep '\.js' static-assets.txt | sort -u > js-urls.txt
   wget -i js-urls.txt -P ./js-files/ --no-clobber -q
   ```
2. Run LinkFinder against each file (or against the live app) to extract endpoint-shaped
   strings (paths, relative URLs, API routes) from the JS source:
   ```bash
   python3 linkfinder.py -i https://example.com/static/app.bundle.js -o cli
   # or point it at a whole domain to auto-discover + crawl + extract
   python3 linkfinder.py -i https://example.com -d -o results.html
   ```
3. Run SecretFinder for API keys, tokens, and credential-shaped strings:
   ```bash
   python3 SecretFinder.py -i https://example.com/static/app.bundle.js -o cli
   python3 SecretFinder.py -i js-files/ -o secrets-report.html
   ```
4. jsluice for more structured extraction (URLs + secrets + a queryable AST-based approach),
   useful on heavily minified/webpack-bundled code:
   ```bash
   jsluice urls js-files/*.js | sort -u > jsluice-urls.txt
   jsluice secrets js-files/*.js
   ```
5. TruffleHog against the downloaded JS directory for high-confidence secret patterns
   (AWS keys, private keys, common token formats) with entropy + regex detectors:
   ```bash
   trufflehog filesystem ./js-files/ --json > trufflehog-js.json
   ```
6. Manual regex sweep as a cheap complement/sanity check for anything the tools miss
   (internal hostnames, debug flags, feature-flag names):
   ```bash
   grep -rEoh "https?://[a-zA-Z0-9.-]+\.(internal|corp|local|dev)[^\"' ]*" js-files/ | sort -u
   grep -rEoh "(api[_-]?key|secret|token|bearer)[\"'\s:=]+[A-Za-z0-9_\-]{16,}" js-files/ -i | sort -u
   ```
7. Consolidate extracted endpoints into the API candidate list for `api-discovery`, and
   any confirmed secrets immediately into evidence per `finding-discipline` (and escalate
   per `opsec-discipline` if a secret appears live/production).

## Tooling

`linkfinder.py` (`-i`, `-d` for domain-wide discovery, `-o cli|html`), `SecretFinder.py`,
`jsluice urls|secrets`, `trufflehog filesystem`, `wget`/`curl` for bulk download, `grep -E`
for manual sweeps. Prefer the structured/JSON outputs (`jsluice`, `trufflehog --json`) over
scraping tool stdout.

## Validation gate

- [ ] Every "secret" found is checked for whether it's actually live/exploitable before
      being reported — plenty of JS contains intentionally-public keys (analytics IDs,
      publishable Stripe keys, public Firebase config) that are not vulnerabilities.
- [ ] Extracted endpoints merged into the `api-discovery` candidate list with source JS
      file noted (for reproducibility).
- [ ] Any secret that looks live/production is flagged for immediate escalation per
      `opsec-discipline`, not left in a routine findings queue.

## Gotchas

- Most "secrets" found in client-side JS are meant to be public (analytics keys, public API
  keys scoped to client use) — confirm actual privilege/scope before treating as a finding;
  this is squarely an Inferred-vs-Demonstrated distinction per `finding-discipline`.
- Minified/bundled JS (webpack, Vite) can obscure real endpoint strings inside template
  literals or dynamically constructed URLs — regex tools miss these; manual review of
  suspicious bundles is sometimes necessary.
- Source maps (`.js.map`) if exposed will deobfuscate everything — check for them explicitly,
  they're a much higher-value target than minified JS:
  ```bash
  curl -s https://example.com/static/app.bundle.js.map -o app.js.map && test -s app.js.map && echo "EXPOSED"
  ```
- A genuinely live/production secret found in JS is time-sensitive — treat it like the
  anonymous-access findings in `service-enumeration`: capture evidence and escalate promptly.
