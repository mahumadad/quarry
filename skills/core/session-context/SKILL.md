---
name: session-context
description: >
  Manage parallel authenticated identities (user A / user B / admin / anonymous) for
  access-control testing. Use before ANY IDOR, broken-access-control, privilege
  escalation, or multi-tenant testing: registers each identity's cookies/tokens in
  engine/sessions.py so cross-identity requests are isolated, reproducible, and
  attributable in evidence. Keywords: session, multi-account, user A user B, cookie
  jar, token refresh, IDOR setup, horizontal privilege, tenant isolation, diff requests.
  Do NOT use for single-user authenticated scanning where no cross-identity comparison
  is needed.
metadata:
  type: core
  phase: mapping
  mitre_attack: [T1078]
  tools: [curl, browser]
depends_on: [identity-map, scope-discipline]
feeds_into: [idor, broken-access-control, broken-access-control, session-management, privilege-escalation]
chains_with: [idor, auth-bypass, business-logic]
---

## Purpose

IDOR and access-control findings live or die on the quality of the identity
setup. Improvised headers cause the two classic failures: (1) sessions get
mixed and a "finding" is actually A reading A's own data, (2) evidence can't
show WHO made the request, so it fails the anti-fabrication bar. This skill
makes identities first-class: one `Session` per test account in
`engine/sessions.py`, credentials from `engine/vault.py`.

## Setup protocol (before hunting starts)

0. **Run an authenticated browser walk before any sweep.** For every role × tenant × plan
   (free/paid) in scope, log in with the correct isolated profile and manually visit the sensitive
   workflows: account/org settings, billing, import/export, uploads, sharing, notifications,
   webhooks, integrations, API tokens, legacy routes and administrative functions. Capture the
   requests, roles, object IDs and state transitions into `identity-map`/`state-map`. Do not inject
   payloads into every registration/profile field by default: active probes require the ROE gate,
   unique markers and reversible fixtures. Missing roles or an incomplete walk are explicit
   coverage gaps, not evidence that authenticated surface was tested.
1. **Inventory identities** from `identity-map`: every role the app has
   (user, premium, org-admin, support, API client...) × every tenant in scope. Record unavailable
   accounts and plan differences instead of silently reducing the matrix.
2. **Minimum viable pair: two same-role accounts in different data scopes**
   (user_a, user_b). Without a pair, NO horizontal access-control finding can
   be demonstrated — `SessionManager.has_pair()` returns False and hunting in
   these classes must not start.
3. **Register each session** with its live material:
   ```python
   Session(name="user_a", role="tenant1-user",
           cookies={"session": "..."}, headers={"X-CSRF-Token": "..."})
   ```
   Passwords stay in the vault; sessions store only live tokens/cookies.
4. **Snapshot an anonymous baseline** too (name="anon", empty material) —
   "unauthenticated can reach X" findings need it.

## Testing discipline

- **Same request, swapped identity.** The canonical test: capture A's request
  to A's own resource, replay verbatim as B (and as anon) changing NOTHING
  else. Any difference attributable only to identity is the signal.
- **Record every cross-identity diff** with `SessionManager.record_diff()` —
  status codes + bodies for both identities. `data_crossed=True` with B's data
  visible in A's response (or vice versa) is the Demonstrated bar for IDOR.
- **Token expiry mid-engagement:** refresh via `update_material()`, never by
  hand-editing commands — stale sessions produce false "access denied" results
  that look like secure behavior.
- **Evidence attribution:** use `curl_flags(name)` to build requests so the
  exact identity used is reproducible from the evidence log.
- **Write actions as B:** never modify A's data while authenticated as B
  without an operator gate — cross-tenant writes can be destructive and are
  usually beyond read-only authorization.

## Response-diff interpretation

| A gets own resource | B gets A's resource | Reading |
|---|---|---|
| 200 + own data | 200 + A's data | IDOR demonstrated |
| 200 + own data | 403/404 | Control present — check method-switching, content-type confusion, parameter pollution before closing |
| 200 + own data | 200 + empty/redacted | Partial — check fields individually (mass-assignment style) |
| 200 | 401 → then 200 after token refresh | Stale session, not a control |

## Gotchas

- **404 ≠ 403.** Apps hiding existence with 404 for foreign objects is a valid
  control; don't report "403 missing" — report what the app actually does.
- **UUIDs don't fix authorization.** Guessable-vs-unguessable IDs change
  exploitability, not whether the control exists. Test with B's known IDs.
- **GraphQL/batch endpoints** often check auth on the operation but not per
  resolved object — diff at the node level, not the query level.
- **Don't stop at read.** If scope allows, test cross-identity UPDATE/DELETE
  and function-level access (B invoking admin endpoints) — but each write test
  is an operator gate.

## Chain Anchors

1. Horizontal read confirmed → enumerate ID pattern breadth (sequentials? UUIDs
   in responses elsewhere?) → mass data extraction potential (feeds
   chain-idor-to-mass-data).
2. Horizontal confirmed → test vertical: B (plain user) invoking admin
   functions from `identity-map`'s role inventory.
3. Any cross-identity write confirmed → operator gate, then assess
   business-logic impact (changing another tenant's settings, prices, ACLs).
