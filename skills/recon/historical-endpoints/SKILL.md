---
name: historical-endpoints
description: >
  Recover forgotten and undocumented endpoints from historical and archived sources, then prove
  which are still live: Wayback Machine / gau / waybackurls / CDX, Common Crawl, JavaScript
  source maps (sourcesContent), and exposed .git history. Dedup by endpoint shape, probe each for
  current reachability, and feed survivors into crawling and hunting. Use early in recon on a web
  target to widen the attack surface beyond the live crawl.
  Keywords: wayback, waybackurls, gau, cdx, common crawl, archived urls, forgotten endpoints,
  source maps, sourcesContent, git history, historical recon, endpoint discovery, deprecated api.
  Do NOT use for live crawling of the current app — use web-crawling. Do NOT use for secret
  scanning as the goal — use js-analysis / github-dorking (this skill finds endpoints, not keys).
metadata:
  type: recon
  phase: recon
  tools: [gau, waybackurls, katana, httpx, git-dumper, python]
depends_on: [passive-recon, js-analysis, subdomain-discovery]
feeds_into: [web-crawling, api-discovery, surface-probes]
chains_with: [info-disclosure, js-analysis]
---

## Signals

- A web/API target where the live crawl likely misses deprecated, staging-leftover, or
  undocumented routes — almost always worth running at the start of web recon.
- Subdomains already enumerated (`subdomain-discovery`) so historical sources can be queried per
  host, not just the apex.
- JavaScript bundles present (source maps may reconstruct original route tables) and/or a `.git`
  directory hinted at by `surface-probes`.

## Prerequisites

- The in-scope host/domain list. Historical sources return URLs for *any* host matching a
  pattern — filter results to in-scope hosts before probing (a Wayback hit for an out-of-scope
  sibling domain is not a license to probe it).
- Agreement that probing recovered URLs (live GET/HEAD) is in scope as ordinary recon; keep it
  rate-limited and read-only.

## Methodology

1. **Pull archived URLs from multiple sources** (coverage comes from using several, not one):
   ```bash
   gau --subs target.example.com > hist_gau.txt
   waybackurls target.example.com > hist_wb.txt
   # Wayback CDX directly (dedup at source, collapse by urlkey):
   curl -s "https://web.archive.org/cdx/search/cdx?url=target.example.com/*&output=text&fl=original&collapse=urlkey" \
     > hist_cdx.txt
   ```

2. **Add Common Crawl** (a source the rest of recon usually skips): query the latest CC index for
   the host and extract original URLs:
   ```bash
   curl -s "https://index.commoncrawl.org/CC-MAIN-2025-latest-index?url=target.example.com/*&output=json" \
     | python3 -c 'import sys,json;[print(json.loads(l)["url"]) for l in sys.stdin]' > hist_cc.txt
   ```

3. **Reconstruct routes from source maps.** Where `js-analysis` found `.map` files, pull
   `sourcesContent` (the original source, not just the `sources` paths) and grep it for route
   tables, API base paths and fetch/axios call sites — these reveal endpoints never present in
   the minified bundle's visible strings.

4. **Mine exposed .git history.** If `.git/` is exposed, dump it and read removed code, not just
   the current tree — deleted endpoints and old route configs live in history:
   ```bash
   git-dumper http://target.example.com/.git/ ./git_dump
   git -C ./git_dump log -p --all | grep -iE '"/(api|v[0-9]+|internal|admin)/' | sort -u
   ```

5. **Normalize and dedup by endpoint *shape*, not literal URL.** Collapse query-string values and
   numeric/UUID path segments to placeholders so `/api/orders/1042?t=1` and `/api/orders/88?t=9`
   become one shape `/api/orders/{id}`. Dedup on the shape; keep one exemplar per shape. This is
   what turns tens of thousands of archived URLs into a reviewable endpoint list.

6. **Probe for live reachability.** Check the *current* status of each unique shape's exemplar —
   many archived URLs are dead, and the value is the ones that still respond:
   ```bash
   cat hist_*.txt | sort -u | httpx -silent -mc 200,201,301,302,401,403 -rl 20 \
     -o hist_live.txt
   ```
   401/403 are kept deliberately — a live-but-protected forgotten endpoint is often the most
   interesting (candidate for `authz-matrix`/`idor`).

7. **Classify and hand off.** Tag survivors: deprecated API versions (`/v1/` still up alongside
   `/v3/`), admin/internal paths, debug/test routes, old auth endpoints. Feed the shape list into
   `web-crawling` (seed URLs), `api-discovery` (versioned APIs) and the relevant hunt skills.

## Tooling

- `gau`, `waybackurls` — archived-URL collectors (configure providers; blacklist noise
  extensions like images/fonts to keep the set reviewable).
- Wayback **CDX** API — direct queries with `collapse=urlkey` for source-side dedup.
- **Common Crawl** index — the source most recon pipelines omit.
- `httpx` — fast, rate-limited live-probe of the recovered set.
- `git-dumper` + `git log -p` — recover endpoints from exposed repository history.
- source-map extraction (`js-analysis`'s tooling) for `sourcesContent`.

## Validation gate (minimum proof)

- A deduplicated list of endpoint shapes recovered from historical/archive/source-map/git
  sources, each tagged with its current live status (and the source it came from).
- For any recovered endpoint used as a finding, a fresh live request/response proving it is
  currently reachable — an archived URL alone proves it *existed*, not that it is live now.

## Gotchas

- **Scope filter first.** Archive sources return out-of-scope hosts freely; filter to the in-scope
  list before any live probe. Do not probe a sibling/vendor domain just because it appeared.
- **Archived ≠ live.** The deliverable is the live subset; always re-probe. Reporting an endpoint
  as present on the strength of a 2019 Wayback capture is an overclaim.
- **Dedup by shape or drown.** Un-normalized archive dumps are tens of thousands of near-duplicate
  URLs; without shape-collapsing the list is unusable and coverage suffers.
- **Rate-limit the probe.** Firing the whole recovered set at full speed can trip WAF/anomaly
  detection and pollute later testing — throttle (`-rl`) and spread it out.
- **Secrets are a different skill.** If source maps / git history also expose keys, hand that to
  `js-analysis`/`info-disclosure`; here the product is endpoints.

## Chains & Compositions

- historical-endpoints → **web-crawling** / **api-discovery** as high-value seed URLs.
- A live forgotten admin/internal endpoint → **authz-matrix** / **idor** / **broken-access-
  control** (old routes often predate current authz hardening).
- Deprecated API version still live (`/v1/` beside `/v3/`) → test the old version for gaps fixed
  only in the new one.
- git history / source-map leakage of config → **info-disclosure**.
