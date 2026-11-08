---
name: quarry:recon
description: Run the reconnaissance phase — passive, active, or both (full, default)
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:recon [--passive|--active|--full]

Runs systematic surface discovery against the active engagement scope.
Defaults to `--full`: passive first, active second, never reversed
(passive does not touch the target and informs how aggressive active
can be).

## Preconditions

- An engagement with phase `SCOPED` or later must exist
  (`.pentest-state/engagement.json`). If it does not exist or the phase
  is `INIT`, stop and point out that `/quarry:engage` is missing.
- Re-read the scope from `.pentest-state/scope.json` before any
  command — do not reuse scope from memory of previous turns, it may
  have changed via `/quarry:scope`.
- The `hooks/hooks.json` guard (`engine/guard.py`) already validates
  each Bash command against scope automatically; even so, before
  building the command, mentally confirm the target is correct.

## Argument

- (none) or `--full` — passive + active, in that order.
- `--passive` — OSINT only, DNS, certificates, public files, GitHub
  dorking, already-served JS. Zero direct scanning requests to the
  target.
- `--active` — assumes useful passive results already exist; if not,
  warn that active without a passive base is less efficient, but proceed
  if the operator insists.

## Methodology (breadth-first, by skill)

Passive (`skills/recon/passive-recon`, suggested order):
1. `dns-enumeration` — DNS records, SPF/DKIM/DMARC, zone transfer attempt
2. `subdomain-discovery` — cert transparency, DNS brute, passive engines
3. `osint` — LinkedIn, Shodan/Censys historical, Wayback Machine
4. `email-harvesting` — email formats, publicly known employees
5. `github-dorking` — org's public repos, leaked secrets, forks
6. `cloud-recon` (passive mode) — public S3/GCS buckets, cloud provider
   subdomains

Active (`skills/recon/active-recon`, requires confirmed scope and
rate/schedule gate from `/quarry:engage`):
7. `port-scan` — nmap with `-oX` for structured output (see `CLAUDE.md`:
   `--help` before the first use of any tool)
8. `service-enumeration` — banner grabbing, versions, fingerprint on
   open ports from step 7
9. `waf-fingerprint` — before any aggressive fuzzing, to calibrate
   aggressiveness
10. `web-crawling` — path spidering, sitemap, robots.txt
11. `js-analysis` — extract endpoints, secrets, comments from JS bundles
    discovered in the crawl
12. `api-discovery` — exposed Swagger/OpenAPI, GraphQL introspection,
    routes inferred from JS
13. `tech-stack-fingerprint` — full stack (frontend, backend, CDN, cloud
    provider) combining everything above
14. `nuclei-reviewed` — select custom checks from `AppProfile` with
    `NucleiRunner`; `safe` profile by default, scope/redirects/OAST
    confined, hashes and JSONL persisted. Matches = leads; zero
    matches ≠ clean target.

For each skill: read its `SKILL.md` in `skills/recon/<skill>/` before
executing — that is where the exact commands and gotchas for that
technique live. If the `SKILL.md` does not exist yet (plugin under
construction), apply the standard methodology for that technique and
flag it in the output as a content gap, do not block recon for it.

## Recording results

- Before executing, query `engine/tool_registry.py` by **capability** (DNS, HTTP probe,
  crawl, JS, content, screenshots, etc.), register the chosen tool/version/backend, and
  use the deterministic fallback. A capability without a backend is `tool_unavailable`, never success.
- Normalize each handoff with `engine/recon_pipeline.py`: discovery → scope filter →
  deduplication → resolution/HTTP → fingerprint → crawl/JS/historicals → screenshots → ranking.
  Each observation preserves source, stage, timestamp, completeness, and metadata; out-of-scope
  candidates are marked `out_of_scope_pending_authorization` and do not proceed to active probes.
- Prioritize by explicit signals (legacy/forgotten, admin, import/export, upload, webhooks,
  integrations, multi-tenant and free/paid differences), storing score and reasons. The score
  orders work; it is not severity or evidence of vulnerability.
- For brute force or fuzzing, index local lists with `engine/wordlists.py` and persist path,
  SHA-256, size, technology, and selection criteria in the run/task. Do not improvise `wordlist.txt`.
- Each new asset is registered with `CoverageTracker.add_asset(asset)`. Each
  discovered endpoint is added with `add_surface`, including method,
  parameters, and known identities; this way `/quarry:hunt` does not collapse
  an entire application into a single cell per host.
- Store complete raw output via `ArtifactStore`, with SHA-256 and index; do not rely on
  truncated terminal views.
- Maintain an `asset-inventory.md` in `<audit_dir>/report/` (Write tool),
  updated incrementally: asset table with type, discovery source,
  priority, and notes. Create snapshot/diff with `TargetDiffEngine` when done.

## Coverage tracking

At the end of the run, print which recon sub-techniques were executed
and which were not (e.g. "cloud-recon: skipped — no cloud provider
usage detected in DNS/certs"). This is not optional — it is the
coverage that `/quarry:status` reports afterwards.

## Edge cases

- **Empty scope or unresolved wildcards only**: before scanning, resolve
  which real hosts fall under the wildcard and confirm them against
  `Scope.is_in_scope()` one by one.
- **Subdomain discovered outside the original scope** (e.g. wildcard
  did not include that apex): do NOT scan it. Register it as
  "discovered, pending authorization" and report it to the operator —
  it may be a legitimate scope expansion that requires an explicit
  `/quarry:scope --add` first.
- **Aggressive WAF/rate-limit detected**: slow down, document the
  observed threshold, do not retry blindly (max 3 identical retries per
  plugin `CLAUDE.md` rule).
- **Rerun on an engagement already at `HUNTING` or later phase**:
  allowed (incremental recon), but warn that already-covered work
  should not be repeated — check `coverage.json` before redoing.

## Phase transition

When done, if the current phase is `SCOPED`, transition to `RECON`
(`state.transition(Phase.RECON)`). If the engagement had already passed
through `MAPPED` or `HUNTING` (incremental recon), do not regress the
phase.

## Expected output

- Table of discovered assets (type, value, source).
- Passive vs active summary of what was executed, with what was skipped
  and why.
- Path of `asset-inventory.md` and the raw outputs.
- Recommended next step: `/quarry:map` (to build the 5 maps before
  hunting) or directly `/quarry:hunt` if the target is simple.
