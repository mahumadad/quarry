---
name: vcenter-attack
description: >
  VMware vSphere / vCenter Server attack methodology for authorized
  engagements: appliance and service enumeration, vCenter SSO (vsphere.local)
  and SAML/STS abuse incl. golden-SAML forgery from vmdir, high-impact
  unauth CVE chains (plugin file-upload RCE, DCERPC memory-corruption RCE),
  and post-credential ESXi / VM / secret extraction. Keywords: vCenter, VCSA,
  vSphere, ESXi, vsphere.local, SSO, vmdir, golden SAML, CVE-2021-21972,
  CVE-2021-21985, CVE-2021-22005, CVE-2023-34048, port 5480, port 902,
  vpxuser, data.mdb. Do NOT use for VMware Workspace ONE / Horizon (different
  products) or for guest-OS internals once you have a shell (windows-privesc
  / linux-privesc) — this is the virtualization control plane.
metadata:
  type: platform
  phase: hunting
  tools: [nmap, curl, nuclei, govc, python-poc, vcenter_saml_login, ldapsearch]
depends_on: [port-scan, service-enumeration, tech-stack-fingerprint]
feeds_into: [chain-analysis, chain-web-to-rce, report-writing]
chains_with: [active-directory, network-infra, windows-privesc, linux-privesc]
---

## Signals
- TCP 443 presenting the vSphere Client (`/ui/`, redirect to `/ui/login`), SDK at `/sdk`, SSO at `/websso/SAML2/SSO/vsphere.local`.
- VCSA management ports: 5480 (VAMI appliance mgmt), 389/636 (vmdir SSO LDAP, `dc=vsphere,dc=local`), 902 (ESXi/vpxa), 8089/8084.
- ESXi host signals: `/ui/` ESXi Host Client, OpenSLP on 427 (legacy), SSH 22, `The VMware ESXi` in TLS cert CN.
- Version strings in `/sdk/vimServiceVersions.xml`, `/clientInfo`, or the login page build number.

## Prerequisites
- Written authorization naming the vCenter/ESXi hosts. The virtualization control plane is maximal blast radius — a vCenter compromise owns every hosted VM (often the whole datacenter, including the DCs). Exploitation and any post-cred action are hard HUMAN GATES per project CLAUDE.md.
- Exact build fingerprint before any CVE path; vCenter CVEs are tightly version-gated and heavily backported.
- Memory-corruption RCE (DCERPC class) requires a tested PoC or it stays **Inferred/Unproven** — never fire untested at a production VCSA (crash = datacenter-wide outage risk).

## Methodology

### 1. Version + service fingerprint (safe)
```bash
curl -sk "https://<vc>/sdk/vimServiceVersions.xml"        # API version surface
curl -sk "https://<vc>/clientInfo"                         # build info on some versions
nmap -p 443,5480,902,389,636,427 -sV <vc>
# SSO realm confirmation:
curl -sk "https://<vc>/websso/SAML2/metadata/vsphere.local" | head
```

### 2. Unauth plugin file-upload RCE chain (vulnerable builds)
```bash
# CVE-2021-21972 (KEV) — vROps vSphere Client plugin: unauth endpoint reachable =>
# path-traversal OVA upload => webshell. SAFE detection probe first (GET, no write):
curl -sk -o /dev/null -w "%{http_code}\n" "https://<vc>/ui/vropspluginui/rest/services/getStatus"
# 200 => endpoint present (Inferred vulnerable). The upload step WRITES a webshell to disk =
# state-changing RCE: HARD HUMAN GATE before executing.

# CVE-2021-21985 (KEV) — vSAN Health plugin unauth RCE via /ui/h5-vsan/rest/proxy/service (default-enabled).
# CVE-2021-22005 (KEV) — Analytics/CEIP file upload RCE via /analytics/telemetry/ph/api/hyper/send.
curl -sk -o /dev/null -w "%{http_code}\n" "https://<vc>/analytics/telemetry/ph/api/hyper/send?_c=test&_i=test"
# A 201/200 on the telemetry endpoint indicates the vulnerable service path; the upload is the gated step.
```

### 3. DCERPC memory-corruption RCE (version-match only)
- **CVE-2023-34048 (KEV), CVE-2024-37079 / 37080, CVE-2024-38812/38813** — pre-auth out-of-bounds write / heap overflow in the VCSA DCERPC implementation. No stable public trigger one-liner; detection is version-match. Label **Inferred** (build in range) or **Unproven**. Any attempt is lab-proof-first + hard human gate — a failed attempt can hang/crash vCenter.

### 4. vCenter SSO / SAML abuse
```bash
# vCenter SSO issues SAML via STS. With foothold/creds to read vmdir (389 on VCSA,
# dc=vsphere,dc=local), the IdP (STS) signing key can be extracted and SAML assertions forged
# for Administrator@vsphere.local => "golden SAML" against vCenter itself.
ldapsearch -x -H ldap://<vc>:389 -b "dc=vsphere,dc=local" -D "..." -w '...' 2>/dev/null | head
# Horizon3 'vcenter_saml_login' automates extracting the IdP key from data.mdb and minting a session.
# This is full admin impersonation — HARD HUMAN GATE and demonstrate with an actual authenticated API call.
```

### 5. Post-credential (SSO admin or root)
```bash
# With Administrator@vsphere.local or VCSA root:
govc about -u 'administrator@vsphere.local:PASS@<vc>'      # confirm session
govc ls / ; govc vm.info -u ... <vm>                       # enumerate inventory
# Extract secrets: vmdir data.mdb, machine SSL cert + private key, vpxuser creds (used by vCenter to
# manage ESXi hosts; decryptable from the vCenter DB to pivot to every ESXi host as root-equivalent).
# ESXi pivot: enable SSH / use the host client; guest VM access via console/VMDK — each is a human gate.
```

## Payloads & Detection Patterns
- **Safe presence probes:** `getStatus` (21972), telemetry endpoint (22005), vSAN proxy path (21985) return a distinguishable code when the vulnerable service is reachable — use these to reach **Inferred**, never to claim RCE.
- **vpxuser blast radius:** vCenter stores encrypted `vpxuser` credentials for every managed ESXi host; recovering and decrypting them yields root-equivalent on each host — the real datacenter-takeover primitive post-cred.
- **Golden SAML persistence:** the STS signing key from vmdir lets you forge valid vCenter sessions indefinitely, surviving password resets — flag the persistence impact explicitly.

## Bypass Techniques
- **Auth bypass via unauth plugins:** the 2021 plugin RCEs need no credentials at all — the "bypass" is that the vulnerable plugin endpoints sit outside the auth boundary. Demonstrate reachability, then gate the write.
- **Golden SAML vs password reset:** forging assertions from the IdP key defeats MFA and password changes because it impersonates the SSO IdP itself, not a user.
- **ESXi direct:** when vCenter is hardened, individual ESXi hosts (OpenSLP 427, host client, SSH) may be softer — fingerprint hosts separately; ESXi ransomware campaigns (e.g. CVE-2021-21974 OpenSLP) rode exactly this gap.

## Chain Anchors
- Unauth plugin RCE → VCSA root → vpxuser decrypt → every ESXi host root → every guest VM.
- Guest VM disk/console access → domain controller VMs → `active-directory` (often the fastest path to DA in a VMware shop).
- vmdir read → golden SAML → persistent vCenter admin → datacenter control.

## Tooling
`nmap`/`curl`/Nuclei for fingerprint + safe presence probes, `govc` for authenticated inventory/post-cred, `ldapsearch` for vmdir, Horizon3 `vcenter_saml_login` / published PoCs (lab-validated) for the SAML and RCE chains. Prefer detection templates and presence probes until a human gate is cleared.

## Validation Gate
- Version/endpoint-presence = **Inferred**. RCE is **Demonstrated** only with command output from the uploaded shell (or tested DCERPC PoC), captured and custody-logged.
- Golden SAML / SSO abuse is **Demonstrated** only when a forged assertion yields an authenticated vCenter API response (capture the session + the API call), not when the signing key is merely extracted.
- vpxuser / ESXi pivot is **Demonstrated** per host only when you actually authenticate to that host; a decrypted credential blob is **Inferred** until used (and using it is a separate gate).
- Record exact build numbers and the precise endpoint/response for every step; backported patches make version inference fragile.

## Gotchas
- **Maximal blast radius, maximal fragility.** vCenter commonly hosts the organization's domain controllers and crown-jewel servers as VMs; a crash from an untested exploit can take down the entire datacenter. Lab-replicate the exact build before any memory-corruption attempt, and gate everything.
- vCenter CVEs are **heavily backported** — a build number can be patched for a CVE without an obvious banner change. Use the safe presence probes where they exist rather than trusting the version alone.
- The 2021 plugin RCEs depend on the plugin being enabled; vSAN Health (21985) is default-enabled but environments disable plugins, so a 404 on the probe means the path isn't there, not that vCenter is safe overall.
- SSO domain is `vsphere.local` by default but can be renamed at install — confirm the real SSO domain before forging SAML or the assertion audience will be wrong.
- Guest-VM access (console, VMDK extraction) crosses into the tenant's data at rest — treat as a distinct, explicitly-authorized human gate even when vCenter admin is already proven.
