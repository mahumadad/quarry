---
name: port-scan
description: >
  Port scanning strategy and commands: nmap SYN/connect/version/script scans, masscan for
  high-speed full-range sweeps, and UDP scanning. Use after active-recon confirms live hosts,
  to enumerate open ports before service-enumeration goes deep on each one. Do NOT use for
  banner grabbing/version detail beyond basic `-sV` — that's service-enumeration's job once
  ports are known.
metadata:
  type: recon
  phase: recon
  tools: [nmap, masscan]
depends_on: [scope-discipline, opsec-discipline, active-recon]
feeds_into: [service-enumeration]
---

## Signals

- Have a confirmed-live host list from `active-recon` and need to know what's open on each.
- Need a fast full-65535-port sweep across many hosts before deciding where to go deep.
- Suspect UDP services (DNS, SNMP, NTP) that a TCP-only scan would miss entirely.

## Prerequisites

- `live-hosts.txt` from `active-recon`.
- Rate/timing policy from `opsec-discipline` — port scanning is the noisiest recon phase so far.

## Methodology

1. Fast full-range TCP sweep to find which ports are open at all, before deep per-host scans:
   ```bash
   nmap -sS -p- -T3 --min-rate 300 -oA fullscan-tcp -iL live-hosts.txt
   ```
   For large host counts, masscan is far faster for this first pass:
   ```bash
   masscan -p1-65535 --rate 1000 -iL live-hosts.txt -oL masscan-full.txt
   ```
2. Narrow nmap deep scan against only the ports masscan/the full sweep found open, per host
   (far more efficient than re-scanning all 65535 ports with scripts):
   ```bash
   # build a per-host open-ports list from the masscan output, then:
   nmap -sV -sC -p 22,80,443,8080 -T3 -oA depth-scan 10.0.0.5
   ```
3. UDP scan — slower and often incomplete (UDP has no handshake, closed-port detection relies
   on ICMP unreachable which is frequently rate-limited or filtered), so scope it to common
   services rather than the full range by default:
   ```bash
   nmap -sU -p 53,67,69,123,161,162,500,514,1900,5060 -T2 --max-retries 2 -oA udpscan 10.0.0.5
   # full UDP range only when specifically justified (very slow):
   nmap -sU -p- -T2 -oA udpscan-full 10.0.0.5
   ```
4. Version detection + default scripts for everything open (bridges into `service-enumeration`
   but a `-sV -sC` pass is the natural output of the port-scan phase):
   ```bash
   nmap -sV -sC -O -p 22,80,443 -oA versioned-scan 10.0.0.5
   ```
5. Firewall/filter detection when results look suspicious (all-filtered, all-open, or
   inconsistent with expected architecture):
   ```bash
   nmap -sA -p 80,443 10.0.0.5          # ACK scan to map firewall rule behavior
   nmap --reason -p 1-1000 10.0.0.5     # shows why nmap classified each port as it did
   ```
6. Save everything in all three nmap output formats for later parsing/reporting:
   ```bash
   nmap ... -oA scanname     # produces scanname.nmap (human), .xml, .gnmap (grepable)
   ```

## Tooling

`nmap` (`-sS` SYN scan requires raw socket privileges/root; `-sT` connect scan as fallback
without privileges; `-sU` UDP; `-sV` version; `-sC`/`--script`; `-oA`/`-oX` structured output
per the project's CLI anti-hallucination rule), `masscan` (`--rate`, `-oL`/`-oJ`). Run `nmap -h`
and `masscan --help` before first use this engagement to confirm available flags on this build.

## Validation gate

- [ ] Scan rate matches `opsec-discipline` policy for this target class.
- [ ] Structured output (`-oA`/`-oX`/masscan `-oJ`) saved, not just terminal scrollback.
- [ ] Open-port list filtered to hosts within `scope.txt` before handing to `service-enumeration`.
- [ ] UDP scope and timing explicitly chosen, not left at a slow default that eats the whole
      time budget for marginal value.

## Gotchas

- `-sS` (SYN scan) needs raw socket capability (root/CAP_NET_RAW) — falls back silently to
  `-sT` in some setups, changing behavior and log footprint without obvious warning.
- masscan's default rate is extremely aggressive and can flood a network link or trigger
  automatic IDS blocking — always set `--rate` explicitly, never run it unthrottled against
  production.
- UDP scan results are inherently less reliable than TCP — a port reported "open|filtered"
  is not confirmed open; treat it as Inferred until confirmed with a protocol-specific probe
  in `service-enumeration`.
- Full-range UDP scans can take hours per host — scope to expected services unless there's
  specific justification and time budget for it.
- Results that look "all open" or "all closed" across an entire range usually mean a
  firewall/IPS is answering on behalf of the real hosts, not that the hosts are actually
  that way — cross-check with `-sA`/`--reason` before reporting.
