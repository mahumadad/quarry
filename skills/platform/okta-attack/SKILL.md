---
name: okta-attack
description: >
  Okta Identity Cloud attack methodology for authorized engagements: tenant
  and user enumeration, OIDC/SAML auth-flow abuse, lockout-aware password
  spraying via the Authentication API, SSWS/OAuth API token abuse, and MFA
  push fatigue / factor downgrade. Keywords: Okta, IdP, SSO, OIDC, SAML,
  /api/v1/authn, SSWS token, Okta Verify, push fatigue, MFA fatigue, factor
  enumeration, DelAuth, org2org, password spray. Do NOT use for Entra ID /
  Azure AD (see entra-attack) or on-prem Active Directory (see
  active-directory); use this only when Okta is the identity provider.
metadata:
  type: platform
  phase: hunting
  tools: [curl, okta-cli, CrowdView, ROADtools-not-applicable, hydra, custom-python]
depends_on: [subdomain-discovery, osint, email-harvesting]
feeds_into: [chain-analysis, chain-auth-to-takeover, report-writing]
chains_with: [entra-attack, oauth, saml, 2fa-bypass, credential-testing]
---

## Signals
- Login redirect to `https://<tenant>.okta.com` or `https://<tenant>.oktapreview.com`, or a custom domain CNAME'd to Okta (`login.target.com` → `*.okta.com`).
- SAML/OIDC metadata referencing `okta.com` issuer (`https://<tenant>.okta.com/oauth2/default` or `/app/<id>/sso/saml/metadata`).
- `okta-` cookies (`sid`, `DT`, `JSESSIONID`) or the Okta sign-in widget JS (`okta-sign-in.min.js`) served by the target app.
- Email harvest / OSINT shows employees using `@target.com` with Okta-backed SSO apps (check `https://<tenant>.okta.com/app/UserHome` redirect behavior).

## Prerequisites
- Written authorization that explicitly names the Okta tenant and permits identity-layer testing. Password spraying against an IdP can lock out real employee accounts and page a SOC — this is a stateful, human-gated action per project CLAUDE.md.
- For unauthenticated enumeration: just the tenant hostname.
- For authenticated paths: one valid low-privilege Okta credential, a leaked SSWS API token, or an OAuth client_id/secret for an Okta service app.
- Confirm the Okta deployment model first: **Classic Engine** vs **Okta Identity Engine (OIE)** — auth-flow behavior and endpoints differ materially (see Gotchas).

## Methodology

### 1. Tenant / deployment fingerprint (unauthenticated)
```bash
# Confirm tenant and whether it is Classic or OIE
curl -s "https://<tenant>.okta.com/.well-known/okta-organization" | jq .
# pipeline:"idx" => OIE; pipeline:"v1" => Classic Engine
curl -s "https://<tenant>.okta.com/.well-known/openid-configuration" | jq '.issuer, .authorization_endpoint, .token_endpoint'
```

### 2. User existence / factor enumeration (lockout-aware)
```bash
# Classic Engine: /api/v1/authn leaks whether a user exists via error code.
# E0000004 = auth failed (user may exist), E0000095/E0000085 differ for locked/unknown.
# Send ONE probe per username with a deliberately wrong password, low rate, and
# STOP at the first lockout signal. This is enumeration, not spraying.
curl -s -X POST "https://<tenant>.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"user@target.com","password":"wrong-on-purpose-'$RANDOM'"}' | jq '.status, .errorCode'
```
- On OIE, `/api/v1/authn` is often disabled; enumeration shifts to the Interaction Code (`/oauth2/<as>/v1/interact` → `/idp/idx/introspect`) flow, which is far less verbose. Treat OIE user-existence enumeration as **Inferred** unless you can show a reproducible oracle.

### 3. Lockout policy discovery BEFORE any spray
```bash
# Burn ONE throwaway account you control (or one explicitly authorized) to measure
# the lockout threshold and window empirically. Record attempts-to-lock and reset time.
# Do NOT spray until the threshold is known — staying at threshold-1 per window is the gate.
```

### 4. Disciplined password spraying (Authentication API)
```bash
# Classic Engine only. One password, many users, spaced UNDER the measured lockout
# threshold per account per window. Single season/year password is the classic pick.
python3 spray_okta.py --tenant <tenant> --users users.txt \
  --password 'Target@2026' --max-per-window 1 --window 3600 --stop-on-lock
# A 'status":"SUCCESS"' or 'status":"MFA_REQUIRED"' response = valid password (MFA_REQUIRED
# still proves the credential). Record exact response as evidence.
```

### 5. MFA factor downgrade / push fatigue (post valid password)
```bash
# After MFA_REQUIRED, /api/v1/authn returns _embedded.factors — enumerate available factors.
# Look for a weaker enrolled factor (SMS, Okta Verify push) you can target.
curl -s -X POST "https://<tenant>.okta.com/api/v1/authn/factors/<factorId>/verify" \
  -H "Content-Type: application/json" -d '{"stateToken":"<token>"}'
# Push fatigue: repeated verify calls spam the victim's Okta Verify. This is an intrusive
# user-targeting action — HUMAN GATE. Only with explicit per-target sign-off; never blind-blast.
```

### 6. API token abuse (if an SSWS token or OAuth app creds are in scope/leaked)
```bash
# SSWS tokens carry the privileges of the creating admin. Validate scope before assuming impact.
curl -s "https://<tenant>.okta.com/api/v1/users?limit=1" -H "Authorization: SSWS <token>"
# OAuth-for-Okta service app (client_credentials) — check granted scopes
curl -s -X POST "https://<tenant>.okta.com/oauth2/v1/token" \
  -u "<client_id>:<client_secret>" -d 'grant_type=client_credentials&scope=okta.users.read'
```

## Payloads & Detection Patterns
- **User-exists oracle (Classic):** differential `errorCode` / HTTP timing between known-good and random usernames on `/api/v1/authn`. Confirm the oracle with a control set before trusting it.
- **SAML assertion tampering:** if the target consumes Okta SAML, pull the assertion and test the Service Provider (not Okta) for signature-wrapping / unsigned-assertion acceptance — that is an SP bug, cross-reference the `saml` hunt skill.
- **Open redirect in `fromURI` / `RelayState`:** Okta's `/login/login.htm?fromURI=` and app `RelayState` have historically been abused to bounce OIDC/SAML responses; test for host-allowlist bypass and chain into token theft (`open-redirect` + `oauth` skills).

## Bypass Techniques
- **DelAuth / AD-agent fallback:** orgs using Delegated Authentication validate passwords against on-prem AD via the Okta AD agent. A valid password here is also a valid AD credential — pivot to `active-directory`. (CVE-2024-0981-class AD-agent username-caching bug: label **Unproven** unless you reproduce the exact precondition.)
- **Sign-on policy gaps:** app-level sign-on policies can exempt specific networks/zones from MFA. Enumerate whether your source IP lands in a trusted zone that drops MFA — demonstrate by completing a sign-in without a factor, don't assume from policy text.
- **Legacy auth / Classic app on OIE tenant:** some tenants keep Classic `/api/v1/authn` alive for legacy apps even after OIE migration; find it and you regain the verbose oracle.

## Chain Anchors
- Valid Okta credential + DelAuth → on-prem **AD** credential (`active-directory`).
- Okta session cookie theft (via app XSS) → full SSO app access (`chain-xss-to-account-takeover`).
- Okta-federated into **Entra ID / AWS** → cloud pivot (`entra-attack`, `aws-attack`).
- SSWS admin token → tenant takeover (create admin user, add federation) — HUMAN GATE before any write.

## Tooling
`curl` + `jq`, custom Python for rate-controlled spraying, Okta's own `/api/v1` REST surface, `CrowdView`/public tenant-enum helpers, SAML Raider (Burp) for assertion work. Prefer hand-rolled rate-limited scripts over off-the-shelf sprayers so lockout control is explicit.

## Validation Gate
- A valid credential is **Demonstrated** only when `/api/v1/authn` returns `SUCCESS` or `MFA_REQUIRED` with the sessionToken/stateToken captured — a non-`E0000004` error alone is **Inferred** at best.
- User-existence oracles must be shown against a control set (known-valid vs known-invalid) in the same run, with the differential recorded — otherwise label **Inferred**.
- MFA push fatigue is reportable only if you demonstrate a completed auth via an approved push; an un-answered push storm is an intrusive action, not a finding.
- SSWS/OAuth token impact = the actual privileged action performed in a scoped test, not the token's nominal scope string.

## Gotchas
- **OIE vs Classic is the single biggest variable.** Most public "Okta user enumeration" writeups target Classic `/api/v1/authn`; on OIE that endpoint is frequently disabled and the IDX flow is deliberately uniform. Fingerprint first (step 1) and don't report a Classic-only oracle against an OIE tenant.
- Password spraying an IdP is **loud and stateful**: Okta ThreatInsight can auto-block your source IP and lockouts page the customer's SOC. Measure lockout empirically (step 3) and treat spraying as a human-gated, rate-limited action.
- `oktapreview.com` is the Okta **preview/sandbox** tenant — confirm whether it is in scope; it often holds test data but is a different environment from production `okta.com`.
- A valid Okta password under DelAuth is a valid **AD** password — flag the blast radius explicitly; this is often higher impact than the Okta finding itself.
- ThreatInsight and network zones mean findings are IP-sensitive: a bypass that works from a trusted zone may fail from the open internet. Record the exact source context for every result.
