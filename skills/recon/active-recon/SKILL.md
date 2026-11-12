---
name: active-recon
description: >
  First direct contact with target infrastructure — live host discovery and basic service
  probing before full port scanning. Use after passive-recon has produced a candidate host
  list, to confirm which hosts are actually alive before investing scan time on them. Do NOT
  use for the deep port/service work — that's port-scan and service-enumeration; this skill
  only answers "is anything there."
metadata:
  type: recon
  phase: recon
  tools: [nmap, fping, masscan, curl]
depends_on: [scope-discipline, opsec-discipline, passive-recon]
feeds_into: [port-scan]
---

## Signals

- Have a candidate host/subdomain/IP list from `passive-recon` or `subdomain-discovery` and
  need to know which are actually up before scanning all of them in depth.
- Need a quick live/dead pass across a large CIDR range before a full port scan.

## Prerequisites

- Candidate host list filtered against `scope.txt` (`scope-discipline`).
- Rate-limit/timing policy confirmed (`opsec-discipline`) — this is the first skill that
  actually sends packets to the target.

## Methodology

1. ICMP sweep across a range (works only where ICMP isn't filtered — many targets block it):
   ```bash
   fping -a -g 10.0.0.0/24 2>/dev/null          # alive hosts via ICMP echo
   nmap -sn -PE 10.0.0.0/24 -oG - | grep Up      # nmap ping sweep, grepable output
   ```
2. Where ICMP is filtered (common), use TCP/ARP-based discovery instead:
   ```bash
   nmap -sn -PS80,443,22 10.0.0.0/24             # TCP SYN ping on common open ports
   nmap -sn -PA80,443 10.0.0.0/24                # TCP ACK ping, bypasses some stateless filters
   arp-scan --localnet                           # same-subnet only, L2 ARP sweep
   ```
3. For web hosts specifically, confirm liveness with an HTTP probe rather than relying on
   ICMP/TCP ping alone (many hosts answer HTTP but drop ICMP):
   ```bash
   httpx -l candidates.txt -silent -status-code -title -tech-detect -o live-web-hosts.txt
   # or minimal curl equivalent
   while read h; do curl -s -o /dev/null -w "%{http_code} $h\n" "https://$h"; done < candidates.txt
   ```
4. For large external ranges, masscan is faster for a first-pass liveness+common-port check
   before handing off to nmap for depth:
   ```bash
   masscan -p80,443,22 10.0.0.0/16 --rate 1000 -oL masscan-livehosts.txt
   ```
5. Consolidate into a confirmed-live host list for `port-scan`:
   ```bash
   awk '{print $1}' masscan-livehosts.txt | sort -u > live-hosts.txt
   ```

## Tooling

`nmap -sn` (host discovery mode, no port scan), `fping`, `arp-scan`, `masscan` (liveness-only
pass, low port count), `httpx` (ProjectDiscovery) for web-specific liveness. Run `--help` on
each before first use this engagement.

## Validation gate

- [ ] Every probed host/IP is within `scope.txt`.
- [ ] Rate matches the `opsec-discipline` policy for this target (first live traffic to the
      target — don't default to aggressive timing).
- [ ] Confirmed-live list is saved as an artifact for `port-scan` to consume.

## Gotchas

- ICMP-only liveness checks massively undercount live hosts behind firewalls that drop ping
  but still serve TCP — always pair with a TCP/HTTP probe.
- A host answering on 80/443 but not ICMP is extremely common (cloud LBs, CDNs) — don't mark
  it "down" from a ping sweep alone.
- masscan at default/high rate can look like a DoS attempt to the target's monitoring and
  may breach the `opsec-discipline` rate policy — always set `--rate` explicitly.
- CDN/WAF-fronted hosts (Cloudflare, Akamai) will answer for the CDN edge, not the origin —
  liveness here confirms the CDN is up, not the origin server; see `waf-fingerprint` and
  `tech-stack-fingerprint` before assuming you're scanning the real backend.
