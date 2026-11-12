---
name: ct-log-enum
description: >
  Certificate Transparency log enumeration across all apex domains in scope.
  Queries crt.sh (and optionally certspotter, censys) to discover historical
  and current hostnames with issued certificates — often reveals subdomains
  that subfinder and DNS brute-force miss (internal tools, dev environments,
  service meshes). Use as a mandatory companion to passive-recon; subfinder
  alone does NOT cover CT logs completely.
  Keywords: certificate transparency, crt.sh, CT logs, subdomain enumeration,
  certificate search, certspotter, censys certificates.
metadata:
  type: recon
  phase: recon
  tools: [curl, jq]
depends_on: [scope-discipline, passive-recon]
feeds_into: [subdomain-discovery, dns-enumeration, active-recon]
---

## Signals

- Engagement just completed `passive-recon` and has an apex domain list.
- subfinder results look thin for the target's expected size.
- Need to discover internal tooling, dev environments, or service mesh
  hostnames that wouldn't appear in DNS brute-force wordlists.

## Prerequisites

- `scope.txt` with all apex domains from `scope-discipline`.
- No target interaction required — queries go to CT log aggregators only.

## Methodology

1. **Query crt.sh for every apex domain in scope** — use the `%.domain`
   wildcard to catch all issued certificates:
   ```bash
   for domain in $(cat scope-domains.txt); do
     curl -s "https://crt.sh/?q=%25.${domain}&output=json" \
       | jq -r '.[].name_value' \
       | sed 's/\*\.//g' \
       | sort -u > "ct-${domain}.txt"
     echo "${domain}: $(wc -l < "ct-${domain}.txt") entries"
     sleep 2
   done
   ```
   Note: crt.sh rate-limits aggressively. Space requests 2s apart. If it
   returns non-JSON (HTML error page), retry after 30s or switch to the
   SQL interface.

2. **Deduplicate and merge with existing subdomain lists:**
   ```bash
   cat ct-*.txt | sort -u > ct-all-subdomains.txt
   comm -23 ct-all-subdomains.txt <(sort existing-subdomains.txt) > ct-new-hosts.txt
   echo "New hosts from CT not in prior recon: $(wc -l < ct-new-hosts.txt)"
   ```

3. **Classify hosts by naming pattern** — internal tooling, dev, prod,
   services:
   ```bash
   grep -Ei '(argocd|grafana|headlamp|traefik|jenkins|gitlab|harbor|vault|consul|prometheus|kibana|sentry|openpanel|status)' ct-all-subdomains.txt > ct-infra-tooling.txt
   grep -Ei '(dev|staging|pre|qa|pentest|sandbox|test|uat|demo|beta)' ct-all-subdomains.txt > ct-nonprod.txt
   grep -Ei '(api|gateway|ws|grpc|graphql|rpc)' ct-all-subdomains.txt > ct-apis.txt
   ```

4. **Resolve new hosts and check for RFC1918 leaks** (see post-processing
   below):
   ```bash
   while read -r host; do
     ips=$(dig +short A "$host" 2>/dev/null | head -3)
     echo "$host $ips"
   done < ct-new-hosts.txt > ct-resolved.txt
   grep -E '\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' ct-resolved.txt > ct-rfc1918-leaks.txt
   ```

5. **HTTP triage of live new hosts** — quick status check without deep
   probing:
   ```bash
   httpx -l ct-new-hosts.txt -sc -title -tech-detect -o ct-httpx-triage.txt
   ```

## Post-Processing: RFC1918 Leak Detection

After ANY subdomain enumeration (this skill, subfinder, DNS brute-force),
run this check on the resolved IP list:

```bash
grep -E '\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)' resolved-ips.txt > rfc1918-in-public-dns.txt
```

Any A record in public DNS pointing to a private IP is an information
disclosure finding (CWE-200): it reveals internal network topology,
microservice names, and sometimes developer identities from subdomain
slugs.

## Tooling

`curl` against crt.sh JSON API, `jq` for parsing, `dig` for resolution,
`httpx` for HTTP triage. Optional: `certspotter` API, `censys` search API
(requires free API key).

## Validation Gate

- [ ] Every apex domain in scope was queried (not just the primary one).
- [ ] New hosts were diffed against the existing subdomain list — duplicates
      removed before active probing.
- [ ] RFC1918 leak check ran on all resolved IPs.
- [ ] All discovered hostnames filtered against `scope.txt` before handoff.

## Gotchas

- crt.sh returns wildcard entries (`*.example.com`) — strip the `*.` prefix
  before deduplication.
- CT logs include expired and revoked certificates — hosts may no longer
  exist. This is a candidate list, not confirmed-live; resolve before
  reporting.
- Large organizations can have 1000+ CT entries. Paginate or use the SQL
  interface for completeness.
- crt.sh often returns HTTP 502/503 under load. Retry with exponential
  backoff (2s, 5s, 15s). If persistently down, fall back to certspotter.
- Some entries are for SAN (Subject Alternative Name) certificates covering
  multiple unrelated domains — filter by the apex domains in scope.

## Chain Anchors

CT-discovered hosts often reveal:
1. **Internal tooling** (ArgoCD, Grafana, Vault) → forced browsing targets
2. **Dev/staging environments** → softer defenses, same codebase
3. **Service mesh names** → SSRF targets if reachable from the app
4. **Employee names in subdomains** → OSINT/social engineering fuel
