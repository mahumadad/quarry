---
name: service-enumeration
description: >
  Deep-dive on services found open by port-scan: banner grabbing, precise version detection,
  and protocol/service-specific nmap NSE scripts. Use once open ports are known, to identify
  exactly what's listening and its version before deciding what vuln-hunting to do. Do NOT
  use this to discover ports in the first place — that's port-scan; this skill assumes a
  known open-port list and goes deep on each one.
metadata:
  type: recon
  phase: recon
  tools: [nmap, nc, curl, openssl, smbclient, enum4linux, ldapsearch]
depends_on: [port-scan]
feeds_into: [waf-fingerprint, tech-stack-fingerprint, api-discovery]
---

## Signals

- Have a confirmed open-port list per host from `port-scan` and need exact service/version.
- Need protocol-specific enumeration (SMB shares, SNMP community strings, LDAP anonymous bind).
- Preparing the inventory that `finding-discipline`/hunting skills will match against known CVEs.

## Prerequisites

- Per-host open-port list from `port-scan`.

## Methodology

1. Manual banner grab for anything a script might misidentify — cheap and often more reliable
   than automated detection for simple text protocols:
   ```bash
   nc -nv 10.0.0.5 22
   nc -nv 10.0.0.5 25
   curl -sI https://10.0.0.5:443 --insecure
   ```
2. nmap version detection with intensity turned up for ambiguous services:
   ```bash
   nmap -sV --version-intensity 9 -p 22,80,443,8080 10.0.0.5
   ```
3. Protocol-relevant NSE script categories — run `safe` scripts by default, `vuln`/`exploit`
   only with explicit sign-off per `opsec-discipline` (some are intrusive):
   ```bash
   nmap -sV --script=default,safe -p 80,443 10.0.0.5
   nmap --script=http-title,http-headers,http-methods -p 80,443 10.0.0.5
   nmap --script=ssl-enum-ciphers,ssl-cert -p 443 10.0.0.5
   nmap --script=smb-os-discovery,smb-enum-shares,smb-enum-users -p 445 10.0.0.5
   nmap --script=ftp-anon,ftp-syst -p 21 10.0.0.5
   nmap --script=mysql-info,mysql-empty-password -p 3306 10.0.0.5
   nmap --script=rdp-enum-encryption -p 3389 10.0.0.5
   ```
4. Service-specific deep tools where nmap scripts aren't enough:
   ```bash
   smbclient -L //10.0.0.5 -N                      # anonymous SMB share listing
   enum4linux -a 10.0.0.5                            # full SMB/RPC enumeration
   ldapsearch -x -h 10.0.0.5 -b "dc=example,dc=com"  # anonymous LDAP bind test
   snmpwalk -c public -v2c 10.0.0.5                  # default community string check
   ```
5. TLS/SSL detail beyond nmap's script (cipher suites, cert chain, protocol versions):
   ```bash
   openssl s_client -connect 10.0.0.5:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text
   nmap --script ssl-enum-ciphers -p 443 10.0.0.5
   testssl.sh https://example.com                    # comprehensive TLS config audit
   ```
6. Build the consolidated service inventory (host, port, protocol, product, version) —
   this is the artifact `finding-discipline` and vuln-matching work consumes:
   ```bash
   nmap -sV -oX services.xml -iL live-hosts.txt -p- 
   # parse to CSV for the engagement inventory
   python3 -c "import xml.etree.ElementTree as ET; ..." services.xml > services.csv
   ```

## Tooling

`nmap` (`-sV`, `--version-intensity`, `--script`), `nc`/`ncat`, `curl -I`, `openssl s_client`,
`testssl.sh`, `smbclient`, `enum4linux`, `ldapsearch`, `snmpwalk`. Confirm script availability
with `nmap --script-help <name>` before relying on it — NSE script sets vary by nmap build.

## Validation gate

- [ ] Only `safe`/`default` NSE categories run without explicit sign-off; anything in `vuln`/
      `exploit`/`intrusive` categories confirmed against `opsec-discipline` first.
- [ ] Version strings recorded verbatim (not paraphrased) — exact version matters for later
      CVE correlation.
- [ ] Anonymous-access findings (open SMB shares, anonymous LDAP/FTP, default SNMP strings)
      captured with full command output as evidence immediately — these are time-sensitive.

## Gotchas

- Version strings can be deliberately spoofed/hardened (banner changed, headers stripped) —
  don't treat a "no version returned" result as "no vulnerable version," just as unconfirmed.
- `nmap --script vuln` is convenient but several scripts in that category are intrusive
  (can crash services, trigger account lockouts) — treat it like an exploitation action,
  not routine enumeration.
- A version string alone is Inferred evidence at best for any specific CVE — per
  `finding-discipline`, it does not become Demonstrated until you trigger the actual behavior.
- SNMP community-string and default-credential checks can lock out accounts or alert
  monitoring just like login brute force — respect the same caution as active credential testing.
