---
name: passive-recon
description: >
  Passive information gathering that never touches the target directly — WHOIS, DNS
  records via public resolvers, certificate transparency logs, Wayback Machine history,
  and Google dorking. Use at the very start of an engagement, before any active scanning,
  to build an initial picture with zero footprint on the target. Do NOT use for anything
  that sends traffic to the target itself — use active-recon or port-scan for that.
metadata:
  type: recon
  phase: recon
  tools: [whois, dig, curl, crt.sh, waybackurls, gau, googler]
depends_on: [scope-discipline]
feeds_into: [dns-enumeration, subdomain-discovery, osint, github-dorking, email-harvesting, ct-log-enum]
---

## Signals

- Engagement just moved from SCOPED to RECON (see `engagement-flow`).
- Need initial domain/org/IP-range info before any active tool runs.
- Need historical content (old endpoints, parameters, pages) without hitting the live site.

## Prerequisites

- `scope.txt` with target domains/orgs from `scope-discipline`.

## Methodology

1. WHOIS on the apex domain — registrant org (confirms ownership), name servers,
   registration/expiry dates, sometimes abuse contact:
   ```bash
   whois example.com
   whois -h whois.arin.net "n 1.2.3.0/24"     # reverse: who owns an IP block
   ```
2. Certificate transparency logs — fastest way to enumerate historical and current
   hostnames issued certs for the domain, including forgotten subdomains:
   ```bash
   curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
   ```
3. Public DNS lookups via resolvers only (no direct queries to the target's own NS yet —
   that's active and belongs in `dns-enumeration`):
   ```bash
   dig +short A example.com @8.8.8.8
   dig +short MX example.com @1.1.1.1
   dig +short TXT example.com @8.8.8.8
   dig +short NS example.com @8.8.8.8
   ```
4. Wayback Machine / historical crawl data — reveals old parameters, endpoints, and pages
   that may still be reachable or hint at app structure:
   ```bash
   # list all known URLs for the domain
   echo example.com | gau --subs > wayback-urls.txt
   # or directly from the CDX API
   curl -s "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey" > wayback-raw.txt
   # waybackurls (tomnomnom) as an alternative/complement
   echo example.com | waybackurls > wayback-urls2.txt
   ```
5. Google dorking for exposed files, login portals, error messages, and indexed internal paths:
   ```bash
   site:example.com filetype:pdf
   site:example.com inurl:admin
   site:example.com intitle:"index of"
   site:example.com ext:sql | ext:env | ext:log
   site:example.com inurl:wp-content "error" OR "warning" OR "fatal"
   ```
   Run via a browser or `googler "site:example.com filetype:env"` if installed; Google
   actively rate-limits/CAPTCHAs scripted queries, so pace these manually if automating.
6. **Mine Wayback URLs for tokens and secrets** — historical URLs often leak JWTs, API keys,
   and session tokens in query strings:
   ```bash
   grep -Ei 'eyJ[A-Za-z0-9_-]{10,}\.' wayback-urls.txt > jwt-in-urls.txt
   grep -Ei '(api[_-]?key|token|secret|key=)[=&][A-Za-z0-9_\-]{16,}' wayback-urls.txt > token-in-urls.txt
   ```
   Forward hits to `jwt` (for JWT analysis) and `info-disclosure` (for key validation).
7. Consolidate: merge crt.sh hostnames, wayback hostnames, and dork results into a single
   candidate hostname list for `dns-enumeration`/`subdomain-discovery` to validate.
   ```bash
   cat crtsh.txt wayback-urls.txt | grep -oP '([a-z0-9-]+\.)+example\.com' | sort -u > candidates.txt
   ```
8. **RFC1918 leak check** — after resolving candidates, flag any A records
   pointing to private IPs in public DNS (information disclosure, CWE-200):
   ```bash
   while read -r host; do
     ip=$(dig +short A "$host" @8.8.8.8 | head -1)
     echo "$host $ip"
   done < candidates.txt > resolved.txt
   grep -E '\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)' resolved.txt > rfc1918-leaks.txt
   ```
   Any hit reveals internal network topology. See `ct-log-enum` for the
   full post-processing pattern.

## Tooling

`whois`, `dig`/`host` (against public resolvers only — `@8.8.8.8`, `@1.1.1.1`), `curl` against
`crt.sh`'s JSON endpoint, `gau`, `waybackurls`, `jq`, manual/`googler` dorking. Run `--help`
on any of these before first use this engagement per the project's CLI anti-hallucination rule.

## Validation gate

- [ ] Every hostname found is checked against `scope.txt` before being carried into active-recon.
- [ ] No request was sent directly to the target's own infrastructure (only to crt.sh,
      archive.org, public resolvers, and search engines).

## Gotchas

- crt.sh frequently has duplicate/wildcard entries (`*.example.com`) and dead subdomains —
  this is a candidate list, not a confirmed-live list; resolve it in `dns-enumeration`.
- Wayback data can be years stale — treat old endpoints as hypotheses to verify, not
  current attack surface.
- WHOIS privacy services hide registrant info for most domains now — don't expect PII;
  focus on name servers and registration dates for infra clues (e.g. recently registered
  = possibly a phishing/test domain, not the real target).
- Google dork volume will get your scripted queries CAPTCHA'd fast — space them out or do
  them manually in a browser session.
