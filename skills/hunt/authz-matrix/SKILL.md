---
name: authz-matrix
description: >
  Systematic multi-identity authorization matrix: replay every captured request under each
  provisioned identity (A, B, higher-privilege, and anonymous) and diff the responses to
  surface broken access control at scale, instead of spot-checking one endpoint at a time.
  Use after a request corpus exists (crawl/HAR/proxy history) and at least two identities are
  provisioned — this is the breadth sweep that feeds idor and broken-access-control.
  Keywords: authorization matrix, autorize, multi-identity diff, horizontal access, vertical
  access, BOLA sweep, access-control coverage, response diffing, identity replay, anonymous
  reachability.
  Do NOT use to prove a single IDOR in depth — use idor for the focused two-account proof.
  Do NOT use for authentication/session forgery — use auth-bypass.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-285, CWE-639, CWE-284]
  mitre_attack: [T1078]
  tools: [burp, autorize, curl, python]
depends_on: [session-context, identity-map, web-crawling]
feeds_into: [chain-analysis, idor, broken-access-control]
chains_with: [idor, broken-access-control, api-abuse, mass-assignment]
---

## Signals

- A sizeable request corpus exists (proxy history, HAR, crawl, OpenAPI/GraphQL schema) and more
  than one identity is provisioned for the engagement — the preconditions for a sweep rather than
  a one-off IDOR test.
- Multi-tenant / multi-role application where the same endpoints are reachable by many roles and
  the question is *which* endpoint × identity cells leak, not whether one specific ID leaks.
- An API surface large enough that manual per-endpoint authorization testing would miss cells —
  the matrix is about coverage, not depth.

## Prerequisites

- At least two low-privilege identities (A, B) with their own data, ideally one higher-privilege
  identity, plus the anonymous (no-credential) identity — all provisioned for this engagement.
  `engine/sessions.py` tracks these as parallel identities; the minimum pair is mandatory.
- A captured request corpus to replay. Each request should be attributable to the identity that
  legitimately produced it (so the matrix knows the "owner" baseline per cell).
- Agreement on which HTTP methods may be replayed ungated: GET/HEAD/OPTIONS are read-only and may
  be swept freely; PUT/POST/PATCH/DELETE mutate state and need an operator gate before replay.

## Methodology

1. **Build the request corpus and identity set.** Collect each distinct request (method + path +
   relevant params) once. Define the identity set: `A`, `B`, `highpriv` (optional), `anon`.
   Capture each identity's auth material (cookie jar / bearer token) into its own store.

2. **Normalize before diffing.** Strip or template volatile fields so equal-authorization
   responses compare equal: CSRF tokens, timestamps, request IDs, nonces, per-request ETags,
   and the identity's own name/email where echoed. Record the normalization rules used — an
   un-normalized diff produces false "differences" and hides real ones.

3. **Replay the matrix (read methods first).** For every request R legitimately made by its owner,
   re-issue R under each *other* identity and under `anon`, keeping method/path/body identical and
   only swapping the auth material:
   ```bash
   # R = GET /api/orders/1042, owned by A
   for id in A B highpriv anon; do
     code=$(curl -s -o "resp_$id.json" -w "%{http_code}" \
       ${COOKIE[$id]:+-b "${COOKIE[$id]}"} "https://target/api/orders/1042")
     echo "$id -> $code"
   done
   ```

4. **Classify each cell** against the owner baseline, not just by status code:
   - `200 + owner's real data under a non-owner identity` → **broken access control (leak)**.
   - `200 + empty/placeholder` → inconclusive; needs a data-bearing baseline to judge.
   - `200 + the caller's own data` → correct (per-identity scoping working).
   - `401/403/404` → control working (or masking — note 404-as-403 obfuscation).
   - size/shape diff vs. owner baseline → candidate; escalate to `idor` for focused proof.

5. **Anonymous row is its own priority.** Any request that returns owner data with *no* credential
   is the highest-severity cell — sweep the `anon` identity across the whole corpus first.

6. **Write-method cells (gated).** Only after operator sign-off, replay a minimal set of mutating
   requests under a non-owning identity against a disposable test object, then verify the mutation
   landed via a privileged read. Never sweep destructive methods across the whole corpus.

7. **Automate with Burp Autorize** for large corpora: configure the low-priv session as the
   "replay" identity and let it diff every proxied high-priv request, flagging
   `Bypassed!`/`Is enforced?` per request — but still hand-confirm flagged cells with the
   normalization rules from step 2 before reporting.

## Tooling

- Burp Suite + **Autorize** — the standard engine for the two-session replay-and-diff sweep.
- `curl` with per-identity cookie jars / token env vars — scriptable matrix for APIs.
- `engine/sessions.py` (`record_diff()`) — records per-identity response diffs with the
  interpretation table; use it to keep the matrix auditable.
- A small diff harness (python `difflib` / JSON structural diff) for normalized body comparison.

## Root Causes

- Authorization enforced per-UI or per-route but not per-object/per-tenant at the data layer.
- "Is authenticated" middleware mistaken for "is authorized for this object/action."
- Some endpoints in a family hardened (detail view) while siblings (export, list, bulk, GraphQL
  field) share no common guard.

## Validation Gate (minimum proof)

- A specific cell (request × identity) where a non-owning or anonymous identity received the
  owner's genuine data or executed a privileged action, with request + normalized response +
  owner baseline captured for that one cell.
- A coverage statement: which requests were swept under which identities, and which cells were
  skipped and why (e.g., mutating methods left ungated).
- Each confirmed leak promoted to an `idor` / `broken-access-control` finding with its own
  focused proof — the matrix locates, the dedicated skill proves.

## Gotchas

- **Normalization is the whole game.** Most false positives are volatile fields; most false
  negatives are over-aggressive normalization that erases the leaked field. Record the rules.
- **Coverage, not exfiltration.** The matrix flags cells; it does not loop the ID space pulling
  records — that bulk step is gated and belongs to `idor`/pii handling.
- **Common N/A:** differing responses that are both the *caller's own* correctly-scoped data are
  not a finding — the diff must show cross-owner leakage.
- **Overclaim trap:** a `200` size-diff alone is a candidate, not a confirmed leak; confirm the
  content is another identity's real data before reporting.
- **404-as-403:** an app that returns 404 for unauthorized objects can hide a leak that only
  shows up on a valid cross-owner ID — pair the sweep with known cross-owner IDs, not random ones.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Anonymous reach** — Does any cell leak to the no-credential identity (worst case)?
2. **Write cells** — Do mutating methods leak under a non-owning identity, not just reads?
3. **Family consistency** — Do list/detail/export/delete siblings of a leaking endpoint share the
   same gap, or only the one cell found?
4. **Privilege direction** — Does a low-priv identity reach high-priv actions (vertical), owner
   data of peers (horizontal), or both?
5. **Blast radius** — From the leaking cells, roughly how much of the object/tenant space is
   exposed?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- authz-matrix → **idor** for each horizontal leak's focused two-account proof.
- authz-matrix → **broken-access-control** for vertical/privileged-action cells.
- authz-matrix → **mass-assignment** when a body field flips ownership in a leaking write cell.
- authz-matrix → **api-abuse** when GraphQL/batch endpoints expose per-resolver authz gaps.
