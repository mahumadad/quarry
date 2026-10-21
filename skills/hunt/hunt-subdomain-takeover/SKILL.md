---
name: hunt-subdomain-takeover
description: >
  Hunt for dangling DNS records pointing to deprovisioned cloud resources
  (CNAME to an unclaimed S3 bucket, Azure/Heroku/GitHub Pages/Fastly/Netlify
  endpoint, etc.) allowing an attacker to claim the resource and serve
  content under the victim's subdomain. Use during recon on any in-scope
  domain with many subdomains. Keywords: subdomain takeover, dangling
  CNAME, NXDOMAIN, fingerprint, CNAME chain.
  Do NOT use for takeover of expired top-level domains (different legal/
  scope considerations) — flag separately and get explicit operator
  authorization before any registration action.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-350]
  mitre_attack: [T1584.001, T1583.001]
  tools: [subfinder, amass, dnsx, httpx, "can-i-take-over-xyz"]
depends_on: [active-recon]
feeds_into: [chain-analysis]
chains_with: [hunt-oauth, hunt-crlf-injection, hunt-clickjacking]
---

## Signals

- Subdomain resolves via CNAME to a known cloud/SaaS domain pattern (`*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.github.io`, `*.herokuapp.com`, `*.fastly.net`, `*.netlify.app`, `*.wordpress.com`, `*.zendesk.com`, `*.shopify.com`, `*.unbouncepages.com`, `*.readme.io`, `*.statuspage.io`).
- HTTP request to the subdomain returns a provider-specific "not found"/"no such app" error page distinct from a generic 404.
- Subdomain appears in old marketing material, DNS zone exports, or `security.txt`/`CAA`/certificate transparency logs but the service it pointed to has been decommissioned.

## Prerequisites

- Full subdomain enumeration for the in-scope domain(s) — passive first, active only within scope.
- A list of known "vulnerable CNAME fingerprint" services (maintained community list, e.g. `can-i-take-over-xyz` project) to pattern-match error responses.
- **Before claiming any resource**, explicit operator authorization — claiming a bucket/app, even for PoC, creates a real external resource and must be cleaned up; this is a human-gated action per project rules.

## Methodology

1. **Enumerate subdomains (passive).**
   ```bash
   subfinder -d target.com -all -silent -o subs.txt
   amass enum -passive -d target.com -o subs_amass.txt
   cat subs.txt subs_amass.txt | sort -u > all_subs.txt
   ```

2. **Resolve and grab CNAME chains.**
   ```bash
   dnsx -l all_subs.txt -cname -resp -silent -o cnames.txt
   # flag anything resolving to NXDOMAIN but still having a CNAME record
   dnsx -l all_subs.txt -cname -silent | while read -r line; do
     host=$(echo "$line" | awk '{print $1}')
     cname=$(echo "$line" | awk '{print $2}')
     dig +short "$cname" | grep -q . || echo "DANGLING: $host -> $cname"
   done
   ```

3. **Probe live HTTP/HTTPS responses for provider fingerprints.**
   ```bash
   httpx -l all_subs.txt -silent -status-code -title -location -o http_probe.txt
   ```
   Look for these classic fingerprint strings in the body:
   - S3: `NoSuchBucket` / `The specified bucket does not exist`
   - GitHub Pages: `There isn't a GitHub Pages site here.`
   - Heroku: `No such app`
   - Azure: `404 Web Site not found`
   - Fastly: `Fastly error: unknown domain`
   - Shopify: `Sorry, this shop is currently unavailable.`
   - Unbounce: `The requested URL was not found on this server.` + Unbounce branding
   - Netlify: `Not Found - Request ID:`

4. **Cross-reference against a maintained fingerprint database** (manually or scripted) rather than relying on memory — fingerprints and vulnerable/non-vulnerable status change as providers patch:
   ```bash
   grep -i -f fingerprints.txt http_probe_bodies/*.html
   ```

5. **Confirm exploitability (not just the fingerprint).** Many providers now require domain verification before serving content for an unclaimed CNAME — a fingerprint match is **Inferred**, not **Demonstrated**, until you actually attempt the claim:
   ```bash
   # S3 example: check if the bucket name (from the CNAME) is unclaimed and creatable
   aws s3 ls s3://dangling-bucket-name --no-sign-request
   # "NoSuchBucket" + ability to `aws s3 mb` it (in a controlled, authorized test AWS account)
   # confirms takeover is live; do NOT leave attacker content hosted there.
   ```
   For GitHub Pages / Heroku / Netlify-style takeovers, confirm by registering the exact matching free-tier resource name under a test account you control, pointing nothing public at it, and verifying the subdomain now serves your test page — then immediately document and tear it down.

6. **Check wildcard DNS masking** — some orgs have `*.target.com` wildcarded to a catch-all, which can hide or create false positives for individual dangling records; verify each candidate individually, not just via wildcard response.

## Tooling

- `subfinder`, `amass` (passive enumeration).
- `dnsx` (bulk CNAME/A resolution, dangling detection).
- `httpx` (bulk HTTP probing with status/title/fingerprint extraction).
- Community fingerprint list (`can-i-take-over-xyz` / EdOverflow's list) kept current — providers patch takeover vectors over time, always re-verify against the latest list rather than a cached one.

## Root Causes

- DNS CNAME record left pointing at a cloud resource (bucket, app, page) after that resource was deleted/unsubscribed, with the DNS record never cleaned up.
- Provider allows any new customer to claim a resource name that matches an existing, still-pointed-to CNAME, without verifying DNS ownership first.
- No periodic DNS hygiene process (zone diffing against active cloud inventory) at the target org.

## Validation Gate (minimum proof)

- DNS resolution output showing the dangling CNAME (`dig`/`dnsx` output with timestamp).
- HTTP response body showing the provider's distinct "unclaimed" fingerprint.
- **Demonstrated** tier requires an actual controlled claim-and-serve test (own content, immediately torn down) with before/after screenshots — do only with explicit operator authorization given the external footprint created.
- Without the claim step, label the finding **Inferred** and say so explicitly in the report.

## Gotchas

- **Minimum proof:** a fingerprint match alone is Inferred — providers change takeover eligibility frequently (e.g. AWS now requires bucket region/ownership checks in many cases); don't claim Demonstrated without the claim test.
- **Common N/A:** CNAME points to a resource that still resolves and serves the *target's own* content (not dangling) — this is just a normal third-party integration, not a finding.
- **Overclaim trap:** reporting every `*.cloudfront.net`/`*.amazonaws.com` CNAME as "potential takeover" without checking the specific fingerprint and current provider patch status creates noise — verify each one.
- Claiming a resource, even temporarily, is an action with real-world footprint (billing, abuse reports, DNS propagation delay) — get sign-off, document start/end time, and tear down immediately after capturing evidence.
- Wildcard DNS and load-balanced CNAMEs with health checks can produce false "dangling" signals that self-heal — re-test before reporting.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Full takeover confirmation** — Can you actually claim the dangling resource (register on the unclaimed service) and serve content from the subdomain, not just observe a dangling CNAME?
2. **Cookie/session scope abuse** — Does the takeover let you set or read cookies scoped to the parent domain, stealing session data from sibling subdomains?
3. **CORS/CSP trust abuse** — Is the taken-over subdomain listed as a trusted origin in CORS or CSP policy elsewhere in the app, enabling a further chain?
4. **Phishing/malware hosting** — Can the takeover host convincing phishing content under the trusted domain?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Claimed subdomain → host arbitrary content under victim's domain → phishing/credential harvesting with a trusted-looking origin, or OAuth `redirect_uri` registered to that subdomain (chain with hunt-oauth).
- Claimed subdomain → set permissive CORS/cookies scoped to the parent domain → session/token theft from the real app if cookies are scoped `Domain=.target.com` (chain with hunt-session-management).
- Claimed subdomain hosting a clickjacking frame of the real login page (chain with hunt-clickjacking).
