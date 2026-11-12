---
name: info-disclosure
description: >
  Hunt for information disclosure: verbose error messages/stack traces, sensitive response
  headers, exposed source code/backup files, and directory listing. Use as a breadth-first
  pass across the whole target early in an engagement, and whenever a feature throws
  unexpected errors.
  Keywords: information disclosure, stack trace, debug mode, verbose error, directory
  listing, .git exposure, .env exposure, backup file, source map leak, server banner,
  X-Powered-By, sensitive header, swagger/openapi exposure, exception leak.
  Do NOT use for data leaked specifically through a broken authorization check (that's
  idor) or through a confirmed injection vector (sqli/xxe/ssrf own their specific data-
  leak findings) — this skill covers disclosure that requires no exploitation primitive at
  all, just observation of what the app exposes by default/misconfiguration.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-200, CWE-209, CWE-538]
  mitre_attack: [T1592, T1082]
  tools: [curl, ffuf, gitleaks, trufflehog, nuclei, waybackurls]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis, credential-harvest, sqli, auth-bypass]
chains_with: [sqli, auth-bypass, ssrf, deserialization]
---

## Signals

- Default/debug error pages left enabled in production (Django `DEBUG=True`, Flask debugger,
  Rails `config.consider_all_requests_local`, ASP.NET YSOD, PHP `display_errors=On`).
- `.git`, `.svn`, `.env`, `.DS_Store`, `web.config`, `.htaccess`, backup files (`*.bak`, `*~`,
  `*.old`, `*.sql`, `*.zip`) reachable directly over HTTP.
- Directory listing enabled on any static asset path.
- Verbose headers: `Server`, `X-Powered-By`, `X-AspNet-Version` revealing exact software
  versions.
- Exposed API documentation/schema (`/swagger.json`, `/openapi.json`, `/graphql` introspection
  — cross-ref graphql) revealing internal endpoints not meant for public consumption.
- Source maps (`*.js.map`) shipped in production, letting you reconstruct original source from
  minified bundles.
- Comments in HTML/JS left in from development (`TODO`, `FIXME`, internal hostnames, commented-
  out credentials).
- Cloud storage buckets/object URLs guessable or linked from the app with public-read
  permissions.

## Prerequisites

- None beyond standard recon access — this is one of the lowest-barrier hunt categories and
  should be run early and broadly across the whole target.
- A wordlist of common sensitive paths/backup extensions for the sweep step.

## Methodology

1. **Error-triggering sweep** — send malformed input to several endpoints and inspect for
   verbose errors:
   ```bash
   curl -s "https://target/api/users/abc"        # type confusion on an expected-int param
   curl -s "https://target/api/search?q=%00"      # null byte
   curl -s -X POST https://target/api/login -d "malformed{{json"
   curl -s "https://target/nonexistent-path-xyz"  # custom 404 vs framework default?
   ```
   Grep responses for stack-trace fingerprints:
   ```bash
   curl -s "https://target/api/users/abc" | grep -Eio \
     "traceback|stack trace|at [A-Za-z0-9_.]+\(|Exception in thread|django\.core|werkzeug|\.rb:[0-9]+:in"
   ```

2. **Sensitive file/path sweep:**
   ```bash
   for p in ".git/config" ".git/HEAD" ".env" ".DS_Store" "web.config" ".htaccess" \
            "backup.zip" "db.sql" "config.php.bak" "wp-config.php.bak" ".svn/entries" \
            "composer.json" "package.json" ".well-known/security.txt"; do
     code=$(curl -s -o /dev/null -w "%{http_code}" "https://target/$p")
     echo "$p -> $code"
   done

   ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -u "https://target/FUZZ" -mc 200 -o sensitive_files.json -of json
   ```
   If `.git/HEAD` returns 200, dump the whole repo and inspect history for leaked secrets:
   ```bash
   git-dumper https://target/.git/ ./dumped_git
   cd dumped_git && git log --all --oneline
   trufflehog filesystem ./dumped_git --json > git_secrets.json
   gitleaks detect --source ./dumped_git --report-path gitleaks_report.json
   ```

3. **Directory listing check:**
   ```bash
   curl -s https://target/uploads/ | grep -i "index of\|<title>Directory listing"
   curl -s https://target/static/ | grep -i "index of"
   ```

4. **Header/banner fingerprinting:**
   ```bash
   curl -sI https://target/ | grep -Ei "^(server|x-powered-by|x-aspnet-version|x-generator):"
   ```
   Cross-reference the exact version string against known CVEs — per project rules, a matching
   version is **Inferred** at most until an actual exploit confirms impact; don't report it as
   a standalone finding beyond "outdated/verbose version banner."

5. **API schema/documentation exposure:**
   ```bash
   for p in "swagger.json" "swagger-ui.html" "api-docs" "openapi.json" "v2/api-docs" \
            "graphql" ".well-known/openid-configuration"; do
     curl -s -o /dev/null -w "$p -> %{http_code}\n" "https://target/$p"
   done
   ```
   If exposed, review the schema for endpoints not discovered through normal crawling —
   feed newly found routes back into the overall endpoint map for other hunt skills.

6. **Source map and JS bundle review:**
   ```bash
   curl -s https://target/static/js/main.abc123.js.map -o main.js.map
   # reconstruct original source structure from the map for review
   grep -o '"sources":\[[^]]*\]' main.js.map
   ```

7. **Historical/archived endpoint discovery** (often surfaces old, forgotten, more verbose
   endpoints no longer linked from the current UI):
   ```bash
   waybackurls target.com | tee wayback_urls.txt
   cat wayback_urls.txt | grep -Ei "\.(bak|sql|zip|env|config|log|old)(\?|$)"
   ```

8. **Template-driven nuclei sweep** for known exposure patterns at scale:
   ```bash
   nuclei -l urls.txt -tags exposure,config,backup,git -o nuclei_disclosure.txt
   ```

## Tooling

- `curl`/`ffuf` with SecLists path wordlists — the core sweep technique.
- `git-dumper` — reconstructs an exposed `.git` repository from HTTP access to its objects.
- `trufflehog`/`gitleaks` — secret-scanning any dumped repo/source for hardcoded credentials,
  API keys, private keys.
- `waybackurls`/`gau` — historical URL discovery from web archives.
- `nuclei -tags exposure` — breadth template sweep.

## Root Causes

- Debug/development configuration flags left enabled in the production deployment.
- Build/deploy pipelines that don't exclude VCS directories, environment files, and backup
  artifacts from the web root.
- Static file servers with directory listing enabled by default and never explicitly disabled.
- Source maps generated for production builds without access restriction (common default in
  many frontend build tools unless explicitly turned off for prod).
- API documentation generators (Swagger/OpenAPI) deployed to the same publicly reachable path
  as the API itself, without an auth gate distinguishing "internal dev reference" from
  "public API consumer docs."

## Validation Gate (minimum proof)

- The actual exposed content (error stack trace text, file contents, directory listing HTML,
  header value) captured verbatim in the finding, with the exact request that produced it.
- For `.git`/backup-file exposure: confirmation the dump actually contains real
  application source/config (not an empty/placeholder repo) and, if secrets are found, that
  they're documented as **Demonstrated** only after confirming they're live credentials (don't
  just assume a string that looks like a key is a valid, active one — note as Inferred until
  cross-checked, and never test found credentials against production without a separate gate).

## Gotchas

- **Minimum proof, not a secret-hunting expedition.** If a `.git` dump or exposed `.env`
  contains credentials, the finding is "sensitive file exposed, containing credential-shaped
  data" — validating whether a found credential is live and testing it against other systems
  is a *separate*, higher-risk step needing its own explicit gate per project rules.
- **Common N/A:** a custom, generic error page shown instead of a framework default, even
  though the underlying error occurred — if no internal details leak through, this is the
  control working, not a finding.
- **Common N/A:** version banners present but with no further exploitation attempted — per
  project anti-fabrication rules, "Server: Apache/2.4.49" alone is not a reportable
  vulnerability; it's reconnaissance data that should feed rce/other skills for an actual
  exploit attempt, not be reported standalone as a CVE finding.
- **Overclaim trap:** directory listing on a folder containing only genuinely public static
  assets (CSS/JS/images meant to be public anyway) is a cosmetic/best-practice note, not a
  meaningful information-disclosure finding — the severity hinges on what's actually listed.
- **Overclaim trap:** source maps exposing minified-but-already-public frontend code (no
  secrets, no internal-only logic) is low severity — the real risk is when source maps reveal
  internal API endpoints, hardcoded keys, or business logic not otherwise observable.
- Don't confuse "verbose in a staging/dev environment explicitly in scope and labeled as such"
  with a production finding — note environment context in every disclosure finding.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Credential validity** — Do the leaked credentials/tokens/API keys still work when tested against the live service?
2. **SSRF enablement** — Do leaked internal IPs or hostnames enable a follow-up SSRF probe?
3. **LFI enablement** — Do leaked file paths enable a follow-up LFI/path traversal probe?
4. **Chaining** — Can this disclosure be combined with another open finding to raise severity (e.g. leaked session ID + CSRF)?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Leaked credentials (`.env`, `.git` history, source maps) → **auth-bypass** /
  credential-harvest if validated as live and in scope to test.
- Stack traces revealing exact ORM/query structure → feeds **sqli** payload crafting.
- Exposed internal endpoints (from API docs/wayback) → expands attack surface for every other
  hunt skill; always feed newly discovered routes back into recon before closing this pass.
- Exposed cloud storage/API keys → **ssrf**/cloud-credential chains if the keys grant cloud API
  access.
