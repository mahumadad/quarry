---
name: ntlm-info-disclosure
description: >
  Hunt for internal information disclosure via NTLM/Negotiate authentication on
  internet-exposed IIS/SharePoint/Exchange/RDWeb endpoints. A Type 2 (CHALLENGE) message returned
  by the server leaks internal hostnames, NetBIOS/DNS domain names, DNS forest/tree names and the
  OS build — reconnaissance gold with no credentials. Use when you find endpoints offering
  `WWW-Authenticate: NTLM`/`Negotiate` (OWA/EWS/Autodiscover, SharePoint `_vti_bin`, RDWeb,
  `/aspnet_client`, IIS virtual dirs). Keywords: ntlm info disclosure, type 2 message, ntlmssp
  challenge, internal hostname leak, domain name disclosure, www-authenticate negotiate, owa ews
  autodiscover, sharepoint, rdweb, iis.
  Do NOT use for NTLM relay/credential capture (that is an active-exploitation / lateral-movement
  technique needing a separate gate) — this skill is the passive recon disclosure from the
  challenge message itself.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-200, CWE-209]
  mitre_attack: [T1590, T1592, T1589]
  tools: [curl, nmap, python-requests]
depends_on: [passive-recon, active-recon, tech-stack-fingerprint]
feeds_into: [chain-analysis, info-disclosure, lateral-movement]
chains_with: [info-disclosure, password-reset, lateral-movement]
---

## Signals

- HTTP endpoints responding `401` with `WWW-Authenticate: NTLM` and/or `WWW-Authenticate:
  Negotiate` — the server will emit a Type 2 CHALLENGE if you reply with a Type 1 NEGOTIATE.
- Classic Microsoft surfaces exposed externally:
  - Exchange: `/owa/`, `/ews/`, `/autodiscover/autodiscover.xml`, `/mapi/`, `/rpc/`,
    `/ecp/`, `/oab/`, `/Microsoft-Server-ActiveSync`.
  - SharePoint: `/_vti_bin/`, `/_vti_inf.html`, `/_layouts/`.
  - RD Web / RDG: `/RDWeb/`, `/rpc/rpcproxy.dll`.
  - Generic IIS virtual dirs and `/aspnet_client/` offering integrated auth.
- `Server: Microsoft-IIS/x.y`, `X-Powered-By: ASP.NET`, `X-AspNet-Version` headers.
- Autodiscover/EWS reachable without auth leaking version build numbers in XML/headers.

## Prerequisites

- An identified endpoint that offers NTLM/Negotiate (seen in a `401` `WWW-Authenticate` header).
- The ability to send a raw Type 1 NTLMSSP token and read the base64 Type 2 from the response —
  `curl --ntlm` with throwaway creds, or a small script that posts the fixed Type 1 blob.
- A decoder for the NTLMSSP Type 2 structure (target info AV_PAIRs) — a short Python snippet or a
  known tool; do not trust a tool's parse blindly, verify a field or two by hand.

## Methodology

1. **Confirm the auth offer.** A plain request should surface the challenge-auth header:
   ```bash
   curl -sI https://target/ews/ | grep -i "www-authenticate"
   # expect: WWW-Authenticate: NTLM   and/or   WWW-Authenticate: Negotiate
   ```

2. **Elicit the Type 2 message.** Send any NTLM request; the server answers the Type 1 with a
   base64 Type 2 CHALLENGE in the `WWW-Authenticate: NTLM <base64>` header — no valid credentials
   needed, the leak is in the challenge itself:
   ```bash
   # curl performs the NTLM handshake; throwaway creds are fine — we only want the challenge
   curl -sI --ntlm -u 'a:a' https://target/ews/ | grep -i "www-authenticate: ntlm "
   # → WWW-Authenticate: NTLM TlRMTVNTUAACAAAA...   (the base64 Type 2)
   ```

3. **Decode the target-info block.** Parse the NTLMSSP Type 2 to extract the AV_PAIRs:
   ```python
   # python3 - : decode a Type 2 NTLMSSP challenge, dump the readable target-info fields
   import base64, struct, sys
   raw = base64.b64decode(sys.argv[1])              # the Type 2 base64 string
   assert raw[:8] == b"NTLMSSP\x00" and raw[8:12] == b"\x02\x00\x00\x00", "not a Type 2"
   ti_len, _, ti_off = struct.unpack("<HHI", raw[40:48])
   blob, i = raw[ti_off:ti_off+ti_len], 0
   AV = {1:"NetBIOS-Computer",2:"NetBIOS-Domain",3:"DNS-Computer",4:"DNS-Domain",
         5:"DNS-Tree(Forest)",7:"Timestamp"}
   while i < len(blob):
       t, l = struct.unpack("<HH", blob[i:i+4]); i += 4
       if t == 0: break
       val = blob[i:i+l]; i += l
       if t in (1,2,3,4,5):
           print(f"{AV[t]:20}: {val.decode('utf-16-le', 'replace')}")
   # also: OS version bytes at offset 48 (major.minor.build) when the Version flag is set
   ```
   This yields the internal computer name, NetBIOS + DNS domain, forest/tree DNS name, and
   (when present) the Windows build number — all without authenticating.

4. **Sweep the Microsoft surface.** Repeat against every exposed endpoint; different hosts behind
   a load balancer may leak different internal names, mapping the internal fleet:
   ```bash
   for p in /owa/ /ews/ /autodiscover/autodiscover.xml /rpc/ /mapi/ /RDWeb/ /_vti_bin/; do
     h=$(curl -sI --ntlm -u 'a:a' "https://target$p" | grep -i "www-authenticate: ntlm ")
     echo "$p -> ${h:-no-ntlm}"
   done
   ```

5. **Correlate and record.** Build the internal map: hostname ↔ domain ↔ forest. Note version
   builds against known Exchange/SharePoint CVE baselines (this is recon input, not a CVE finding
   on its own — a version without a demonstrated trigger is not a vulnerability).

## Tooling

- `curl --ntlm` — simplest way to drive the handshake and capture the Type 2 header.
- `nmap --script http-ntlm-info -p 443` (and `smb-os-discovery` for SMB-exposed hosts) — verify
  flags with `--script-help` first; cross-check its parse against the manual decode.
- A short Python NTLMSSP decoder (above) for trustworthy field extraction.
- `python-requests` + `requests_ntlm` only if you need to script the sweep at scale.

## Root Causes

- NTLM/Negotiate (Windows Integrated Authentication) exposed on internet-facing endpoints. The
  Type 2 CHALLENGE message by design embeds the server's target-info block (internal names, build)
  and is returned before any credential is validated — any anonymous client can read it.
- Legacy Exchange/SharePoint/RDWeb published directly to the internet instead of behind a
  pre-auth reverse proxy / modern auth (OAuth/ADFS) that doesn't emit NTLM challenges.
- Default IIS virtual directories left with Windows Authentication enabled and externally reachable.
- No stripping/normalisation of the challenge at the edge (WAF/reverse proxy passing NTLM through).

## Validation Gate (minimum proof)

- **Demonstrated:** a captured Type 2 NTLMSSP challenge from the target, decoded, showing concrete
  internal identifiers (NetBIOS/DNS computer name, NetBIOS/DNS domain, forest/tree DNS name, OS
  build) that are not otherwise public. Include the raw base64, the decode, and the endpoint.
- **Inferred:** the endpoint offers `WWW-Authenticate: NTLM`/`Negotiate` and will clearly perform
  the handshake, but the Type 2 was not yet captured/decoded (e.g. proxy intercepted it) — the
  disclosure vector is present, the leaked values not yet extracted.
- **Unproven:** "IIS is exposed so it probably leaks the domain" with no challenge captured. Do
  not report. Likewise, a software version alone (no demonstrated impact) is recon, not a finding.
- Classify as **information disclosure** (recon value), not as authentication bypass or RCE. Be
  explicit that no credentials were used and nothing was authenticated.

## Payloads & Detection Patterns

| Categoría | Shape | Propósito |
|---|---|---|
| Auth-offer probe | `HEAD` + read `WWW-Authenticate` | find NTLM/Negotiate endpoints |
| Type 1 trigger | `curl --ntlm -u a:a` (throwaway) | elicit the Type 2 challenge |
| Type 2 decode | parse NTLMSSP AV_PAIRs | extract internal names/domain/build |
| Surface sweep | loop OWA/EWS/RDWeb/`_vti_bin` | map internal fleet behind the LB |
| SMB cross-check | `nmap smb-os-discovery` (if 445 exposed) | corroborate hostname/domain/OS |

```bash
# Detection: find NTLM-offering endpoints and capture + decode each challenge.
for p in /owa/ /ews/ /autodiscover/autodiscover.xml /rpc/ /mapi/ /ecp/ /RDWeb/ /_vti_bin/ /; do
  offer=$(curl -sI "https://target$p" | grep -io "www-authenticate: *\(ntlm\|negotiate\)" | head -1)
  [ -z "$offer" ] && { echo "$p -> no-ntlm"; continue; }
  t2=$(curl -sI --ntlm -u 'a:a' "https://target$p" | grep -i "www-authenticate: ntlm " \
       | sed -E 's/.*NTLM //I' | tr -d '\r')
  echo "$p -> offer; type2_len=${#t2}"
  [ -n "$t2" ] && python3 decode_ntlm.py "$t2"     # the decoder from Methodology step 3
done
# A non-empty, decodable Type 2 that yields internal hostnames/domain = Demonstrated disclosure.
```

## Bypass Techniques

| Filtro evadido | Técnica | Notas |
|---|---|---|
| only `/owa` hardened | hit `/ews` `/mapi` `/rpc` `/autodiscover` | sibling vdirs often still emit NTLM |
| reverse proxy strips header | target the origin IP / alternate vhost (Host header) | edge may normalize, origin may not |
| Negotiate (SPNEGO) wrapper | send NTLMSSP inside the GSS-API/SPNEGO blob | Negotiate falls back to NTLM |
| 443 fronted by CDN | probe autodiscover/legacy host from DNS/CT logs | legacy names bypass the CDN |
| WAF blocks `--ntlm` UA | craft the raw Type 1 blob manually | fixed NEGOTIATE token, any client |

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Internal recon feed** — Use the leaked NetBIOS/DNS domain and hostnames to seed further
   enumeration (DNS, CT logs, naming conventions). Chain info-disclosure for the broader map.
2. **Username format inference** — Domain name + any harvested display names → likely
   `domain\user` / UPN format, feeding password-reset enumeration and credential-testing.
3. **Version → CVE lookup** — The OS/Exchange/SharePoint build narrows which CVEs *might* apply;
   treat as a hypothesis requiring a real trigger (do not report the version as a finding).
4. **NTLM relay potential (gate)** — Exposed NTLM may enable relay/capture attacks; this is a
   separate active technique requiring explicit authorization — note the potential, do not execute.
5. **Autodiscover/EWS abuse** — Pre-auth Autodiscover sometimes leaks additional topology; probe
   for further anonymous disclosure on the same host.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- NTLM info disclosure → **info-disclosure** (internal hostname/domain/forest map for recon).
- Leaked domain/user format → **password-reset** (enumeration) / **credential-testing**
  (password spraying `domain\user`).
- NTLM endpoint exposure → **lateral-movement** (relay/capture — separate authorization gate).
- Version builds → variant-analysis / CVE hypothesis (needs a demonstrated trigger to become a
  finding).

## Gotchas

- **This is recon disclosure, not auth bypass.** The Type 2 leaks before credential validation;
  you authenticated to nothing. Don't dress it up as access — its value is the internal
  intelligence it hands you.
- **A version string is not a finding.** Reading an Exchange/SharePoint build from the challenge
  (or headers) and matching a CVE is a *hypothesis*; per anti-fabrication rules it needs a real
  trigger demonstrating impact before it's a vulnerability.
- **Negotiate ≠ always NTLM.** `WWW-Authenticate: Negotiate` may prefer Kerberos; you still often
  get an NTLMSSP fallback, but confirm you actually captured an NTLMSSP Type 2 (`NTLMSSP\0` magic,
  message type `0x02`), not a Kerberos/SPNEGO blob you misread.
- **Don't do relay/capture without a gate.** Escalating from "endpoint offers NTLM" to actually
  relaying a coerced authentication is an active attack with its own scope/authorization — stop
  at disclosure unless explicitly authorized.
- **Load balancers scatter results.** Repeated probes may hit different backends leaking different
  names; capture several and dedupe — one probe undercounts the internal fleet.
- **Common N/A:** the endpoint is behind modern auth (OAuth/ADFS/Entra) or a pre-auth proxy that
  never emits an NTLM challenge — no Type 2, no disclosure. Record tested-and-safe.
