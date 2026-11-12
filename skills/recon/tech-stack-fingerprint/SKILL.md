---
name: tech-stack-fingerprint
description: >
  Identify the target's technology stack — language/framework, web server, CMS, CDN, and
  notable libraries/versions — via Wappalyzer, whatweb, and manual response-header/markup
  analysis. Use after subdomain-discovery/active-recon confirm live hosts, before *
  skills pick techniques specific to a framework/CMS. Do NOT use for WAF/edge-security vendor
  identification — that's waf-fingerprint; this skill is about the application's own
  technology, even though both are often run back to back on the same host.
metadata:
  type: recon
  phase: recon
  tools: [wappalyzer, whatweb, curl, builtwith]
depends_on: [subdomain-discovery, active-recon]
feeds_into: []
---

## Signals

- A live host list exists from `active-recon`/`subdomain-discovery` and the specific
  framework/CMS/server behind each one hasn't been confirmed yet.
- About to choose which * skills are worth running against a target — framework-specific
  techniques (e.g. a known CMS plugin vuln class) only apply once the stack is known.
- A finding references a version-specific behavior and the exact running version needs
  independent confirmation beyond a banner string.

## Prerequisites

- Confirmed-live host list from `active-recon`.
- `opsec-discipline` rate policy for the handful of requests this involves (generally low-
  volume, low-risk compared to brute-force recon steps).

## Methodology

1. **Wappalyzer for the broadest single-pass signal set** (JS frameworks, analytics, CMS,
   server, CDN, e-commerce platform) — fast and low-footprint since it mostly parses what a
   normal page load already reveals:
   ```bash
   wappalyzer https://example.com -oJ wappalyzer-results.json
   ```

2. **whatweb as a cross-check with a different plugin/signature set**, particularly strong on
   server-side fingerprints Wappalyzer sometimes misses:
   ```bash
   whatweb -v -a 3 https://example.com                 # -a 3: aggressive plugin matching
   whatweb --log-json=whatweb-results.json https://example.com
   ```

3. **Manual header inspection** for version strings and stack hints that automated tools can
   miss or under-report, especially on custom/in-house stacks with no CMS signature to match:
   ```bash
   curl -s -I https://example.com/ | grep -iE "server|x-powered-by|x-aspnet-version|x-generator|x-drupal-cache|via"
   ```

4. **Check for framework/CMS-specific marker files and paths** that confirm (or refute) what
   headers/Wappalyzer suggest — many frameworks and CMSes expose predictable static artifacts:
   ```bash
   for p in wp-login.php wp-content/ /sites/default/ .git/HEAD package.json composer.json \
            server-status /actuator/health _next/static/; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com/$p")
     echo "$code  /$p"
   done
   ```

5. **Inspect rendered HTML source and script tags** for generator meta tags, build-tool
   artifacts (webpack chunk naming conventions, Next.js `_next/` paths), and version comments
   that confirm the specific framework/version:
   ```bash
   curl -s https://example.com/ | grep -iE "generator|react|vue|angular|next\.js|wordpress|drupal"
   ```

6. **BuiltWith (web lookup or API) as a historical cross-check**, useful for catching
   technologies that were present at some point (third-party integrations, analytics, past
   CMS) that current live-page scanning might miss if they're loaded conditionally.

7. **Cross-reference findings from `js-analysis`** if already run — bundled JS often reveals the
   exact framework/build tool version in source maps, package metadata, or webpack runtime
   comments more precisely than external fingerprinting.

8. **Note the CDN/edge layer separately from the origin stack**, and hand off to
   `waf-fingerprint` for the security-vendor-specific check — a CDN header (`server: cloudflare`)
   identifies the edge, not necessarily the backend application technology.

9. **Record version numbers with their confidence level explicitly** — a version from a banner/
   header is a *lead* (per `finding-evidence-standards.md`'s Regla 2 equivalent for recon), not
   a confirmed-exploitable fact; it informs which * skill and which known-CVE checks are
   worth attempting, but does not itself become a finding without a real trigger.

## Tooling

`wappalyzer -oJ`, `whatweb -a 3 --log-json`, `curl -I`/`curl -s` for header and markup
inspection, BuiltWith (web/API) for historical cross-check.

## Validation gate

- [ ] At least two independent signals (tool + manual, or two tools) agree before a
      framework/CMS/version is recorded with high confidence — a single Wappalyzer hit alone
      is noted as provisional.
- [ ] Version numbers are explicitly flagged as unconfirmed leads, not findings, until a
      * skill actually triggers version-specific behavior.
- [ ] CDN/edge-layer technology is recorded separately from origin-application technology, with
      a note to run `waf-fingerprint` for the security-vendor-specific layer.
- [ ] Output is consolidated into a per-host stack summary usable by * skills to prioritize
      technique selection.

## Gotchas

- Version banners are frequently stale, deliberately obfuscated, or left over from a base
  image/template and don't reflect what's actually patched — never let a banner version alone
  justify a CVE-based finding (same discipline as `js-analysis`'s and the project's anti-
  fabrication Regla 2).
- `X-Powered-By` and similar headers are often stripped intentionally in production hardening —
  their absence doesn't mean the technology isn't present, just that this particular signal is
  unavailable; rely on multiple signals, not any single header.
- A CDN-fronted host's response headers can reflect the CDN's own stack (e.g. an Nginx header
  from the edge) rather than the origin's actual server — cross-check against direct-to-origin
  evidence where available and in scope, rather than taking edge-observed headers as the origin
  truth.
- Marker-file probing (step 4) sends a handful of requests per host — low-risk but still live
  traffic; batch sensibly rather than hammering many paths at high concurrency, per
  `opsec-discipline`.
- A confirmed CMS/framework doesn't mean its default/well-known vulnerabilities apply — most
  production deployments patch or disable risky defaults; this skill's output narrows which
  * techniques are *worth trying*, it doesn't itself confirm exploitability.
