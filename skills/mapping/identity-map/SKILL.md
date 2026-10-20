---
name: identity-map
description: >
  Map the identity and authentication/authorization model of the target:
  roles, permissions, token types (JWT, opaque session, API key), OAuth/OIDC
  flows, SSO integration, MFA enforcement, and relative privilege levels
  across every identity type the system recognizes (end user, admin,
  service account, third-party integration).
  Use after asset-map to catalogue every way the system authenticates and
  authorizes, before testing auth bypass, IDOR, or privilege escalation.
  Do NOT use for session/cache storage mechanics — use state-map.
  Do NOT use for what each authenticated role can technically *do* at the
  system level (filesystem/network/DB/exec) — use capability-map.
metadata:
  type: mapping
  phase: mapped
  tools: [jwt_tool, burp, mitmproxy, curl, postman, oauth_hijack_tools]
depends_on: [asset-map]
feeds_into: [chain-auth-to-takeover, chain-idor-to-mass-data, chain-analysis, triage-gate]
chains_with: [chain-auth-to-takeover, chain-idor-to-mass-data]
---

## Signals

- You have working credentials/sessions at one or more privilege tiers and need to understand
  the full identity model before testing auth-related findings.
- The target exposes OAuth/OIDC, SAML SSO, or third-party login and you need to trace the
  full flow before looking for flaws in it.
- Multiple token types coexist (session cookie for web UI, JWT for mobile/API, API key for
  server-to-server) and findings in one need to be checked against the others.
- About to test IDOR, privilege escalation, or auth bypass — those tests are only as good as
  the identity model they're checked against.

## Prerequisites

- Completed asset-map with every auth-relevant endpoint identified (login, registration,
  password reset, token issuance, OAuth endpoints, SSO ACS/metadata URLs).
- At least one valid credential per intended privilege tier if the engagement scope allows
  (test accounts provided by the client, or self-registration if permitted).

## Methodology

1. **Enumerate every authentication mechanism.** List each distinct way to authenticate:
   username/password, SSO (which IdP, SAML or OIDC), social login, API key, mTLS, magic link.
   For each, capture the full flow with a proxy (burp/mitmproxy) — every request/response,
   every redirect, every token issued.

2. **Decode and catalogue every token type.** For JWTs: algorithm (`jwt_tool` to check `alg`
   confusion, `none` alg acceptance, weak secret), claims present (role, tenant, scope,
   expiry), where it's issued, where it's validated, and whether validation happens at every
   consumer or only at the edge. For opaque sessions: where state lives (state-map handles
   storage, but note *that* it's opaque here), rotation on privilege change, fixation
   resistance. For API keys: scope, rotation, rate limiting, whether they're bound to an
   IP/origin.

3. **Trace OAuth/OIDC/SSO flows end to end.** Record every parameter in the authorization
   request (`redirect_uri`, `state`, `response_type`, `scope`, `nonce`), whether `redirect_uri`
   is validated by exact match or by prefix/substring, whether `state` is checked on return,
   and where the token exchange happens (front-channel vs back-channel). This flow map is the
   direct input to chain-auth-to-takeover's OAuth+redirect pattern.

4. **Enumerate roles and permissions.** For every role the system recognizes (anonymous, free
   user, paid user, org admin, support staff, super admin, service account), list what
   endpoints/actions are nominally available. Build this from UI enumeration, API schema
   (OpenAPI/GraphQL introspection if exposed), and client documentation — then mark each
   permission as VERIFIED (you tested it and the enforcement matched the claim) or
   UNVERIFIED (claimed but not yet tested).

5. **Map privilege hierarchy and escalation paths.** Order roles by privilege. For each
   adjacent pair, note the exact mechanism that should prevent a lower role from acting as a
   higher one (a role check, a resource-ownership check, a scope claim) — this is the
   predicate that privilege-escalation and IDOR testing will try to break.

6. **Check MFA and step-up auth enforcement.** Where is MFA required vs optional? Is it
   enforced server-side on every sensitive action, or only at login (making session hijack
   post-login sufficient)? Note any step-up auth (re-auth required for sensitive actions) and
   whether it's actually re-validated or just re-prompted client-side.

7. **Map service-to-service and machine identities.** Service accounts, internal API keys,
   webhook signing secrets, CI/CD deploy tokens. These often carry higher effective privilege
   than any human role and are frequently under-protected — feed into trust-map's boundary
   analysis for where these identities cross trust boundaries.

## Validation gate

- Every role/permission claim is tagged VERIFIED or UNVERIFIED with the verifying request/
  response if VERIFIED.
- Every token type has its validation logic (or the fact that it couldn't be determined)
  recorded, not just its format.
- OAuth/SSO flow maps include the actual parameter values observed, not the spec's idealized
  flow — implementations deviate from spec constantly.

## Gotchas

- A role check done client-side (hidden UI button) and absent server-side is a finding in
  itself, not a mapping footnote — but don't stop mapping to write it up mid-pass; flag and
  continue, then formalize later through triage-gate.
- `alg: none` and HS256/RS256 confusion are classic but rare in anything built post-2018 —
  don't assume either way; test it and record the result.
- Multiple JWTs in flight (one for the web session, one for mobile API, one internal
  service-to-service) frequently have *different* validation rigor — map each independently,
  never assume parity.
- "SSO" can mean the IdP is authoritative for identity but the application still maintains
  its own authorization/role store locally, decoupled from IdP group membership — check both
  halves.
- A permission that looks consistent in the UI can differ at the API layer (API allows an
  action the UI never exposes) — always verify against the API directly, not just through the
  rendered UI.
