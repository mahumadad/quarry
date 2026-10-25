---
name: recon-subdomain-enum
description: >
  Subdomain enumeration: passive sources (certificate transparency, DNS datasets,
  search engines), active DNS brute-force, and wildcard detection. Builds the initial
  asset inventory that port-scan and tech-fingerprint consume.
  Keywords: subdomain, crt.sh, subfinder, amass, brute-force, wildcard, cert transparency,
  DNS, asset discovery, attack surface.
metadata:
  type: recon
  phase: recon
  cwe: []
  mitre_attack: [T1596.001, T1596.002]
  tools: [subfinder, amass, dnsx, curl, dig, httpx]
depends_on: [scope-discipline, opsec-discipline]
feeds_into: [recon/port-scan, recon/tech-fingerprint, recon/surface-probes]
---

## Signals

- Engagement includes a root domain (e.g. `target.com`) rather than a single URL.
- Scope permits testing any `*.target.com` or has a defined list of subdomains.
- Client mentions dev/staging/internal environments that may be exposed.

## Prerequisites

- Root domain(s) confirmed in scope.
- Rate limits and testing window from `opsec-discipline`.
- For active brute-force: confirmation that DNS queries at moderate volume are permitted.

## Methodology

1. **Certificate Transparency (passive, fast).**
   Query crt.sh for certificates issued to the domain and its wildcards:
   ```bash
   curl -s "https://crt.sh/?q=%.target.com&output=json" \
     | jq -r '.[].name_value' | sort -u | tee ct-subs.txt
   ```
   This is passive — no traffic hits the target.

2. **Passive aggregator (subfinder).**
   Subfinder queries 30+ passive sources (Shodan, VirusTotal, SecurityTrails, etc.):
   ```bash
   subfinder -d target.com -all -silent -o subfinder-subs.txt
   ```
   With API keys configured in `~/.config/subfinder/provider-config.yaml` the yield
   improves significantly. On the anonlab backend, subfinder uses `HTTP_PROXY` automatically.

3. **Passive + active (amass, optional).**
   Amass adds DNS resolution, ASN correlation, and light brute-force:
   ```bash
   amass enum -d target.com -passive -o amass-passive.txt
   # active mode only if RoE allows:
   amass enum -d target.com -active -brute -o amass-active.txt
   ```

4. **Merge and deduplicate.**
   ```bash
   cat ct-subs.txt subfinder-subs.txt amass-passive.txt \
     | sort -u > all-subs.txt
   wc -l all-subs.txt
   ```

5. **Wildcard detection.**
   Before resolving, check if the domain has a wildcard DNS record:
   ```bash
   dig +short nonexistent-random-string-12345.target.com
   ```
   If this returns an IP, the domain uses wildcard DNS. All resolution results
   must then be filtered against this baseline IP to avoid false positives.

6. **Resolve and filter live hosts.**
   ```bash
   dnsx -l all-subs.txt -a -resp -silent -o resolved.txt
   # HTTP probe for live web services:
   httpx -l all-subs.txt -silent -status-code -title -tech-detect -o live-hosts.txt
   ```

7. **Wayback Machine for historical subdomains.**
   ```bash
   curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original&collapse=urlkey" \
     | jq -r '.[][]' 2>/dev/null | sed 's|https\?://||' | cut -d/ -f1 | sort -u > wayback-subs.txt
   comm -23 wayback-subs.txt all-subs.txt > new-from-wayback.txt
   ```

## Tooling

`subfinder` (passive aggregator), `amass` (passive+active), `dnsx` (bulk DNS resolver),
`httpx` (HTTP prober), `curl` (crt.sh, Wayback), `dig` (wildcard check, manual DNS).

On the anonlab backend: all tools route through Tor automatically via env vars.

## Output

- `all-subs.txt` — deduplicated subdomain list.
- `live-hosts.txt` — live HTTP(S) services with status codes and tech detected.
- `resolved.txt` — DNS A records for all subdomains.
- Wildcard baseline IP (if present) for downstream filtering.

## Validation gate

- [ ] At least two independent passive sources queried (crt.sh + subfinder minimum).
- [ ] Wildcard DNS checked before interpreting resolution results.
- [ ] Only in-scope subdomains retained (cross-checked against `scope-discipline`).
- [ ] Results deduped and stored for port-scan and tech-fingerprint phases.
- [ ] If anonlab backend: all queries went through Tor (no direct DNS leaks).

## Gotchas

- crt.sh can be slow or rate-limit. Cache results; don't hammer it.
- Wildcard DNS makes brute-force results useless unless filtered against the baseline IP.
- Some passive sources require API keys — without them subfinder misses significant coverage.
  Check `subfinder -ls` to see which sources are configured.
- Amass active mode generates real DNS traffic — respect opsec-discipline rate limits.
- Cloud providers (AWS, Azure, GCP) may have thousands of subdomains for large orgs. Filter
  early by checking scope.
