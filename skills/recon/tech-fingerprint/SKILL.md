---
name: recon-tech-fingerprint
description: >
  Technology stack identification: language/framework, web server, CMS, CDN, and notable
  libraries/versions via Wappalyzer, whatweb, httpx, and manual response-header/markup
  analysis. Runs after subdomain-enum and port-scan confirm live hosts. Output narrows
  which hunt-* skills are worth running and which CVE checks apply. Does NOT cover
  WAF/edge-security vendor identification (that's waf-fingerprint).
  Keywords: wappalyzer, whatweb, httpx, tech stack, CMS, framework, version, fingerprint,
  X-Powered-By, generator, CDN, server header.
metadata:
  type: recon
  phase: recon
  cwe: []
  mitre_attack: [T1592.004]
  tools: [wappalyzer, whatweb, httpx, curl, builtwith]
depends_on: [scope-discipline, opsec-discipline, recon/subdomain-enum, recon/port-scan]
feeds_into: [recon/js-analysis, recon/api-discovery, recon/surface-probes, hunt/*]
---

## Signals

- Live host list exists from subdomain-enum/port-scan but the framework/CMS/server behind
  each one hasn't been confirmed yet.
- About to choose which hunt-* skills are worth running — framework-specific techniques
  only apply once the stack is known.
- A finding references version-specific behavior and the exact running version needs
  independent confirmation beyond a banner string.

## Prerequisites

- Confirmed-live host list from `recon/subdomain-enum` or `recon/port-scan`.
- `opsec-discipline` rate policy (low-volume, low-risk compared to brute-force steps).

## Methodology

1. **httpx tech detection (fast, integrated).**
   httpx combines HTTP probing with basic tech detection in a single pass:
   ```bash
   httpx -l live-hosts.txt -silent -tech-detect -status-code -title \
     -server -content-type -o httpx-tech.txt
   ```

2. **Wappalyzer for the broadest single-pass signal set** (JS frameworks, analytics, CMS,
   server, CDN, e-commerce platform):
   ```bash
   wappalyzer https://target.com -oJ wappalyzer-results.json
   ```

3. **whatweb as cross-check** with a different plugin/signature set, strong on
   server-side fingerprints Wappalyzer sometimes misses:
   ```bash
   whatweb -v -a 3 https://target.com
   whatweb --log-json=whatweb-results.json https://target.com
   ```

4. **Manual header inspection** for version strings and stack hints automated tools miss:
   ```bash
   curl -s -I https://target.com/ \
     | grep -iE "server|x-powered-by|x-aspnet-version|x-generator|x-drupal-cache|via"
   ```

5. **Framework/CMS-specific marker files and paths:**
   ```bash
   for p in wp-login.php wp-content/ /sites/default/ .git/HEAD \
            package.json composer.json server-status /actuator/health \
            _next/static/ /graphql __graphql; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$p")
     echo "$code  /$p"
   done
   ```

6. **HTML source inspection** for generator meta tags and build-tool artifacts:
   ```bash
   curl -s https://target.com/ \
     | grep -iE "generator|react|vue|angular|next\.js|wordpress|drupal|magento|vtex"
   ```

7. **BuiltWith (web lookup or API) as historical cross-check**, useful for catching
   technologies present at some point that current scanning might miss.

8. **Cross-reference with js-analysis** if already run — bundled JS often reveals
   exact framework/build tool version in source maps, package metadata, or webpack
   runtime comments more precisely than external fingerprinting.

9. **Note CDN/edge layer separately from origin stack**, hand off to `waf-fingerprint`
   for security-vendor-specific checks.

10. **Record version numbers with confidence level** — a version from a banner/header
    is a lead (Inferred), not a confirmed-exploitable fact. It informs which hunt-*
    skill and CVE checks are worth attempting but does not itself become a finding
    without a real trigger.

### Platform-specific fingerprinting

#### Magento
```bash
curl -s https://target.com/magento_version
curl -s https://target.com/js/mage/ -o /dev/null -w "%{http_code}"
curl -s https://target.com/ | grep -i "magento"
curl -s https://target.com/skin/frontend/ -o /dev/null -w "%{http_code}"
```

#### VTEX
```bash
curl -s -I https://target.com/ | grep -i "x-vtex\|x-powered-by.*vtex"
curl -s https://target.com/api/catalog_system/pub/products/search | head -c 200
curl -s https://target.com/sitemap.xml | head -20
```

#### WordPress
```bash
curl -s https://target.com/wp-json/ | jq '.name, .url' 2>/dev/null
curl -s https://target.com/wp-content/plugins/ -o /dev/null -w "%{http_code}"
curl -s https://target.com/readme.html -o /dev/null -w "%{http_code}"
```

### Anonlab backend (Tor)

On the anonlab backend, all HTTP tools route through Tor automatically via env vars.
For whatweb, use the `web` wrapper:
```bash
web whatweb https://target.com
# or with curl directly (respects HTTP_PROXY):
curl -s -I https://target.com/
```

## Tooling

`httpx` (fast bulk prober with tech detection), `wappalyzer` (broad JS/CMS/framework
fingerprinting), `whatweb` (server-side plugin matching), `curl` (manual header/path
inspection), BuiltWith (historical cross-check).

On the anonlab backend: tools route through Tor via env vars. Use `web` wrapper for
whatweb/nikto.

## Output

- Per-host stack summary: `host → {server, framework, CMS, CDN, versions}`.
- Confidence level for each technology (high: 2+ signals agree; provisional: single signal).
- Version numbers flagged as leads, not findings.
- CDN/edge layer separated from origin technology.

## Validation gate

- [ ] At least two independent signals agree before a framework/CMS/version is recorded
      with high confidence. Single Wappalyzer hit alone is noted as provisional.
- [ ] Version numbers flagged as unconfirmed leads, not findings, until a hunt-* skill
      triggers version-specific behavior.
- [ ] CDN/edge-layer technology recorded separately from origin-application technology.
- [ ] Output consolidated into per-host stack summary for hunt-* skill prioritization.
- [ ] If anonlab: all requests went through Tor (no direct connections).

## Gotchas

- Version banners are frequently stale, deliberately obfuscated, or from a base image/template.
  Never let a banner version alone justify a CVE-based finding.
- `X-Powered-By` and similar headers are often stripped in production hardening. Their absence
  doesn't mean the technology isn't present — rely on multiple signals.
- CDN-fronted host response headers reflect the CDN's stack (e.g. Nginx from the edge), not
  the origin. Cross-check against direct-to-origin evidence where in scope.
- Marker-file probing sends a handful of requests per host — low risk but still live traffic.
  Batch sensibly per `opsec-discipline`.
- A confirmed CMS/framework doesn't mean its default vulnerabilities apply — most production
  deployments patch or disable risky defaults. This skill narrows which hunt-* techniques are
  worth trying, not itself confirm exploitability.
