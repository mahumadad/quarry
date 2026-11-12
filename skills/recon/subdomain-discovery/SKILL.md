---
name: subdomain-discovery
description: >
  Enumerate subdomains via passive aggregators (subfinder, amass, crt.sh), active DNS brute
  force, and permutation/alteration scanning. Use after dns-enumeration to build the full
  subdomain attack surface before active-recon/port-scan touches individual hosts. Do NOT use
  for single-domain record detail (MX/TXT/zone transfer) — that's dns-enumeration; this skill
  is about breadth of hostnames, not depth of records.
metadata:
  type: recon
  phase: recon
  tools: [subfinder, amass, crt.sh, massdns, gobuster, altdns, dnsgen]
depends_on: [scope-discipline, dns-enumeration]
feeds_into: [active-recon, port-scan, tech-stack-fingerprint, cloud-recon]
---

## Signals

- Need the broadest possible subdomain list for a target apex domain before scanning.
- A narrow candidate list from passive-recon/crt.sh feels incomplete (common with large orgs).
- Suspect naming patterns (e.g. `staging-*`, `*-dev`, numbered hosts) that permutation could reveal.

## Prerequisites

- Apex domain(s) confirmed in `scope.txt`.
- Baseline hostnames from `passive-recon`/`dns-enumeration`.

## Methodology

1. Passive aggregation — fast, zero/low footprint, pulls from dozens of sources:
   ```bash
   subfinder -d example.com -all -silent -o subfinder.txt
   amass enum -passive -d example.com -o amass-passive.txt
   ```
2. crt.sh again here as a dedicated pass (if not already pulled in passive-recon), including
   wildcard expansion:
   ```bash
   curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u >> crtsh.txt
   ```
3. Active DNS brute force against a wordlist — confirms existence, finds names not in any
   public source:
   ```bash
   gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o gobuster-dns.txt
   # or massdns for high-volume resolution against a prepared wordlist
   massdns -r resolvers.txt -t A -o S -w massdns-results.txt subdomain-wordlist-with-domain.txt
   ```
4. Active enumeration mode in amass (brute force + recursive + web archives, more aggressive
   and slower than passive):
   ```bash
   amass enum -active -d example.com -brute -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o amass-active.txt
   ```
5. Permutation/alteration on the confirmed set — generates likely variants
   (`dev.example.com` → `dev2.example.com`, `staging-api.example.com`, etc.) and resolves them:
   ```bash
   cat confirmed-subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o S -w permuted-results.txt
   # or altdns
   altdns -i confirmed-subs.txt -o permuted-candidates.txt -w altdns-words.txt
   altdns -i permuted-candidates.txt -r -o altdns-resolved.txt -s altdns-results.txt
   ```
6. Merge, dedupe, filter against scope, and resolve to confirm liveness before handing off:
   ```bash
   cat subfinder.txt amass-passive.txt amass-active.txt crtsh.txt gobuster-dns.txt | sort -u > all-subs-raw.txt
   grep -E "\.example\.com$" all-subs-raw.txt > all-subs-inscope.txt
   httpx -l all-subs-inscope.txt -silent -o live-subs.txt
   ```

## Tooling

`subfinder -all`, `amass enum -passive|-active -brute`, `crt.sh` JSON API, `massdns -r
resolvers.txt`, `gobuster dns`, `altdns`, `dnsgen`, `httpx` for liveness confirmation. Keep
a current `resolvers.txt` (public resolver list) — stale/dead resolvers silently drop results.

## Validation gate

- [ ] Final subdomain list deduped and filtered against `scope.txt`.
- [ ] Liveness-confirmed subset (`httpx` or equivalent) produced for downstream active skills.
- [ ] Brute-force/permutation wordlist size and concurrency logged (for reproducibility and
      rate-limit accountability per `opsec-discipline`).

## Gotchas

- Wildcard DNS (`*.example.com → 1.2.3.4`) makes every brute-force guess "resolve," producing
  massive false positives — detect it first (`dig random-string-1234.example.com`) and if it
  resolves, brute force results are worthless without HTTP-level content diffing.
- Passive sources go stale — a subdomain in subfinder/amass output may be long decommissioned;
  confirm liveness before treating it as attack surface.
- Permutation scans explode combinatorially fast — cap wordlist size and concurrency, this is
  one of the noisiest/slowest steps in recon.
- A resolved subdomain pointing to third-party infra (see `scope-discipline`) is not
  automatically testable even though DNS enumeration found it honestly.
