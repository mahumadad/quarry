---
name: chain-multi-app
description: >
  Build and validate chains that cross an application/trust boundary within the same
  engagement scope — a finding in app A combined with a finding (or just a trust relationship)
  in app B produces impact neither app's isolated testing would surface, e.g. an OAuth token or
  shared-secret leak in app A enabling impersonation in app B. Use when trust-map has flagged
  an org/tenant/SSO/shared-credential boundary between two in-scope applications and findings
  exist (or are suspected) on both sides. Do NOT use for chains confined to a single
  application's own components — that's chain-analysis/chain-graph-walk/the pattern-specific
  chain-* skills; this skill is specifically for the cross-application edge.
metadata:
  type: chain
  phase: chaining
  tools: [chain_engine.py, burp, jwt_tool, curl]
depends_on: [trust-map, chain-analysis]
feeds_into: [finding-validation, report-writing]
chains_with: [chain-auth-to-takeover, chain-graph-walk, chain-custom]
---

## Signals

- `trust-map` identified a shared-authentication relationship between two in-scope
  applications (shared SSO/Authorization Server, shared static secret, a trusted service-to-
  service call, shared session/cookie domain) and both apps are in scope for this engagement.
- A finding in one app yields credential material, a token, or a trust-bearing identifier
  whose validity/acceptance by a *second* app hasn't been tested yet.
- The engagement explicitly covers multiple applications/products under one client (common in
  platform/suite engagements), not a single monolithic app.
- `hunt-oauth`'s client-confusion check (same Authorization Server, multiple `client_id`s)
  surfaced a candidate — this skill is where that candidate gets built into a full chain.

## Prerequisites

- `trust-map` has confirmed (not assumed) the cross-app trust relationship: same IdP/
  Authorization Server, shared secret, shared cookie domain, or a service-to-service trust the
  receiving app doesn't independently re-verify.
- Both applications are explicitly in scope for this engagement — a cross-app chain into an
  application the client didn't authorize is out of scope even if the trust relationship is
  real; see Gotchas.
- At least one finding or confirmed trust-bearing artifact (token, shared secret, session
  cookie) on the originating side (app A).

## Methodology

1. **State the cross-app hypothesis precisely**, mirroring `chain-custom`'s discipline: (finding/
   artifact in app A) → (trust relationship confirmed by trust-map) → (precondition satisfied in
   app B). If the trust relationship isn't independently confirmed — only assumed from shared
   branding or a shared parent company — this isn't ready for a chain attempt yet; go back to
   `trust-map`.

2. **Classify the cross-app trust mechanism explicitly**, since the verification method differs
   by mechanism:
   - **Shared SSO/OIDC Authorization Server** — verify whether app B validates that a token/code
     was issued specifically for *its* `client_id` + registered `redirect_uri`, or accepts any
     valid token from the shared IdP regardless of audience (classic OAuth "mix-up"/client-
     confusion, per `hunt-oauth`'s methodology step 6).
   - **Shared static secret/API key** — verify whether the secret is scoped per-app server-side,
     or whether possessing it (leaked from app A, e.g. via `js-analysis`/`github-dorking`) grants
     equivalent access against app B's API.
   - **Shared cookie domain** (`Domain=.example.com`) — verify whether app B trusts a session
     cookie set by app A's domain without its own independent session validation.
   - **Service-to-service trust** — verify whether app B's internal API trusts a request
     forwarded/relayed by app A without re-authenticating the original end user.

3. **Obtain the trust-bearing artifact from app A's side**, using whichever finding provides it
   (token leak, predictable session ID, leaked API key) — this step's evidence should already
   exist from the originating finding; don't re-derive it speculatively.

4. **Test acceptance on app B independently**, using the artifact obtained from app A, following
   the specific mechanism's verification from step 2:
   ```bash
   # example: replay an app-A-issued token against app B's API
   curl -s -i https://app-b.example.com/api/me -H "Authorization: Bearer $TOKEN_FROM_APP_A"
   # example: replay app A's session cookie against app B if cookie domain is shared
   curl -s -i https://app-b.example.com/account -H "Cookie: session=$APP_A_SESSION"
   ```
   A positive result (app B treats the artifact as valid and returns app-B-scoped data/access)
   is the core evidence for this chain — capture full request/response exactly as any other
   finding would.

5. **Confirm the identity resolved on app B's side is the correct victim, not a coincidence.**
   Verify the returned data/access on app B genuinely corresponds to the same user identity
   compromised on app A (e.g. same email/user ID in the response), not an unrelated default/
   test account that happens to accept the artifact.

6. **Assess combined impact in app B's terms, not app A's.** The severity of "impersonate a user
   in app B" depends on what app B actually exposes/allows — re-derive CVSS/impact fresh for
   the app-B side of the chain rather than assuming it matches app A's original finding
   severity.

7. **Build the minimal end-to-end PoC** spanning both apps: obtain artifact in A → present it to
   B → observe B's acceptance and resulting access, exactly as `chain-custom`'s PoC discipline
   requires, with no destructive action in either app without explicit operator sign-off.

8. **Check whether app B is actually in the engagement's authorized scope** before any of the
   above touches it with live requests — see Gotchas; this is the single most important gate
   specific to this skill.

## Validation gate

- Same four gates as any chain (via `finding-validation`): Refutation, Reachability, Trigger,
  Impact — applied to the cross-app claim specifically, not inherited from app A's or app B's
  individual findings.
- The cross-app trust mechanism is independently confirmed by `trust-map`, not assumed from
  shared branding, shared parent company, or superficial similarity.
- App B's acceptance of the artifact is demonstrated with full request/response evidence, and
  the resolved identity is confirmed to match the compromised app-A user.
- App B is explicitly confirmed in-scope for this engagement before any artifact was replayed
  against it.

## Gotchas

- **Scope is the hard stop here.** A real, interesting cross-app trust relationship into an
  application the client didn't authorize for testing is not a chain to pursue — it's a finding
  about app A's artifact (the leak/token/secret itself) with a *theoretical* note that it may
  affect app B, explicitly flagged as requiring separate authorization before any verification.
  Never send a live request to an out-of-scope app B "just to confirm," even with in-scope
  artifacts in hand.
- A shared parent company or shared design system is not evidence of a trust relationship —
  only `trust-map`'s actual reachability/trust-direction testing (not branding) establishes
  that app B would accept anything from app A.
- Don't let app A's severity carry over to app B by assumption — a low-privilege leak in app A
  could grant admin-equivalent access in app B (escalating severity) or nothing at all if app B
  independently re-validates (killing the chain entirely); only the step-6 re-derivation
  settles it.
- Multi-app chains are disproportionately likely to involve real customer identities across
  systems — handle any identity data surfaced per `opsec-discipline`'s data-handling rule, same
  as any PII finding.
- If app B rejects the artifact outright, that's a valid and useful negative result (confirms
  B's isolation holds) — record it in `noted_but_no_chain_found`-style coverage, not as a
  silent dead end.
