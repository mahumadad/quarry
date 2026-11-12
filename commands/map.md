---
name: quarry:map
description: Generate the 5 Quarry maps (asset, trust, identity, state, capability) for chain-analyst
argument-hint: ""
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:map

Builds the 5 structured maps that `chain-analyst` (and `/quarry:chain`)
use as input. They bridge recon (raw data) and hunting (directed
testing): without maps, hunting becomes ad-hoc and chain-analysis has
nothing to work with.

## Precondition

- Engagement phase must be `RECON` or later, with at least one asset
  registered in `coverage.json`. If `/quarry:recon` never ran, stop and
  recommend it first — maps without recon data are speculation, not
  maps.
- Read `asset-inventory.md` and the raw outputs in `<audit_dir>/raw/`
  before mapping — do not invent trust relationships or roles not backed
  by observation.

## The 5 maps

Each lives in `skills/mapping/<name>/SKILL.md` (methodology) and
materializes as `<audit_dir>/report/maps/<name>.md`.

1. **Asset map** (`asset-map`) — everything discovered in recon,
   normalized: domains, subdomains, IPs, ports/services, API endpoints,
   cloud buckets, repos, mobile apps. Group by "logical system" (e.g.
   everything serving the same frontend), not just by type.

2. **Trust map** (`trust-map`) — trust boundaries and flows between
   assets: what calls what, what crosses a trust boundary (e.g. public
   frontend → internal API → database), what assumes implicit trust in
   a header, internal IP, or unvalidated-origin token. This is what
   later feeds `ssrf`, `cors`, `host-header`.

3. **Identity map** (`identity-map`) — complete authentication model:
   mechanisms (session, JWT, OAuth, API key), roles and their
   privileges, where tokens are issued and validated, whether there are
   multiple tenants and how they are isolated. Feeds `auth-bypass`,
   `jwt`, `oauth`, `idor`.

4. **State map** (`state-map`) — what maintains state and where:
   sessions (server-side vs JWT stateless), caches (CDN, app-level,
   Redis), queues, persistent websockets. Where state can be poisoned
   or read across users. Feeds `cache-poisoning`, `race-condition`,
   `session-management`.

5. **Capability map** (`capability-map`) — what each component/role can
   do: which endpoints mutate data, which are read-only, which actions
   are irreversible or sensitive (payments, deletion, role change),
   which component has what level of network/cloud privilege. Feeds
   `chain-analysis` directly — "capability" is what a finding chain
   ultimately obtains.

## Exact steps

1. For each of the 5 maps, read its `SKILL.md` in
   `skills/mapping/<name>/` if it exists; if not written yet, use the
   definition above and flag it as a content gap without blocking.
2. Build the map as table + relationship list (not free prose — the
   chain-analyst needs to parse this).
3. Write each map to `<audit_dir>/report/maps/<name>.md`.
4. Generate an index `<audit_dir>/report/maps/README.md` linking all 5
   and summarizing in 3-5 lines the most relevant structural finding
   from each (e.g. "trust-map: internal PDF service trusts origin IP
   without validation — SSRF candidate").
5. Transition the phase to `MAPPED` if it was at `RECON`
   (`state.transition(Phase.MAPPED)`).

## Edge cases

- **Insufficient recon for a map** (e.g. no cloud-recon was run, no
  data for cloud infra capability map): leave that map section explicitly
  marked `NO DATA — requires additional recon`, do not fill with
  assumptions.
- **Single-page/simple API target**: all 5 maps are still generated, but
  may be short. Do not omit any — even a "trivial" map (e.g. identity
  map = "static API key only, no roles") is useful information for
  chain-analysis.
- **Re-execution after hunting** (a new asset or role was discovered
  during hunting): update the affected map instead of regenerating
  everything from scratch; note what changed and why in the maps README.

## Expected output

- The 5 map files + index README, with paths.
- List of "NO DATA" entries if any map was left incomplete due to
  missing recon.
- Recommended next step: `/quarry:hunt` (breadth-first across all assets
  and classes).
