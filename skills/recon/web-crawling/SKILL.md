---
name: web-crawling
description: >
  Spider in-scope web applications to extract endpoints, parameters, and forms using
  gospider/hakrawler and related crawlers. Use once live web hosts are confirmed (from
  subdomain-discovery/tech-stack-fingerprint) to build the full set of reachable URLs and
  inputs before js-analysis and api-discovery dig into them. Do NOT use for JS file content
  analysis — that's js-analysis; this skill produces the URL/param/form inventory the other
  two consume.
metadata:
  type: recon
  phase: mapped
  tools: [gospider, hakrawler, katana, burpsuite]
depends_on: [subdomain-discovery, tech-stack-fingerprint]
feeds_into: [js-analysis, api-discovery]
---

## Signals

- Live web hosts confirmed, need the full set of pages/endpoints/parameters/forms before
  hunting begins.
- Wayback/passive URL lists feel incomplete and need live-crawl confirmation.
- About to move into the MAPPED gate (`engagement-flow`) and the URL inventory is the
  missing artifact.

## Prerequisites

- Live, in-scope web host list (`live-subs.txt` or equivalent from `subdomain-discovery`).
- Rate-limit policy from `opsec-discipline` — crawling can generate significant request volume.

## Methodology

1. Baseline crawl with gospider — follows links, JS references, robots.txt, sitemap.xml:
   ```bash
   gospider -s "https://example.com" -o gospider-out -c 10 -d 3 \
     --sitemap --robots --other-source -t 5
   ```
2. hakrawler as a fast complementary crawler, good for piping into other tools:
   ```bash
   echo "https://example.com" | hakrawler -depth 3 -plain > hakrawler-urls.txt
   ```
3. katana (ProjectDiscovery) for JS-aware crawling (renders/parses JS-discovered endpoints
   that a plain HTML crawler misses) and form extraction:
   ```bash
   katana -u https://example.com -d 3 -jc -kf all -fx -o katana-out.txt
   # -jc: crawl endpoints found inside JS files
   # -kf: known files (robots.txt, sitemap.xml, etc.)
   # -fx: extract forms
   ```
4. Explicitly pull robots.txt and sitemap.xml by hand too — cheap and often reveals paths
   crawlers don't reach (disallowed-but-listed paths, staging sitemaps):
   ```bash
   curl -s https://example.com/robots.txt
   curl -s https://example.com/sitemap.xml
   ```
5. For authenticated areas, crawl through Burp Suite with the session active so the crawler
   follows logged-in-only links (unauthenticated crawlers will stop at the login wall):
   ```
   Burp Suite → Target → set scope to example.com → browse the app with Burp's proxy active
   → right-click scope → "Spider this host" (or use Burp's passive crawl via proxy history)
   ```
6. Normalize and dedupe all URLs, split into static assets, pages, and likely API endpoints
   for `api-discovery`:
   ```bash
   cat gospider-out/* hakrawler-urls.txt katana-out.txt | grep -oP 'https?://\S+' | sort -u > all-urls.txt
   grep -E '\.(js|css|png|jpg|svg|woff2?)(\?|$)' all-urls.txt > static-assets.txt
   grep -vE '\.(js|css|png|jpg|svg|woff2?)(\?|$)' all-urls.txt > pages-and-endpoints.txt
   grep -E '/api/|/v[0-9]+/|\.json' pages-and-endpoints.txt > likely-api-endpoints.txt
   ```
7. Extract parameters from crawled URLs for later fuzzing/param-based hunting:
   ```bash
   grep -oP '(?<=\?)[^#]+' all-urls.txt | tr '&' '\n' | cut -d= -f1 | sort -u > param-names.txt
   ```

## Tooling

`gospider` (`-c` concurrency, `-d` depth, `--sitemap --robots --other-source`), `hakrawler`,
`katana` (`-jc`, `-kf`, `-fx`), Burp Suite's proxy/spider for authenticated crawling, `curl`
for manual robots.txt/sitemap.xml pulls.

## Validation gate

- [ ] Crawl depth/concurrency matches `opsec-discipline` rate policy.
- [ ] Only in-scope hosts crawled — a crawler following off-site links will happily leave
      scope if not constrained (`-whitelist`/scope settings).
- [ ] Output split into static assets vs. pages/endpoints vs. likely API routes before
      handing to `js-analysis`/`api-discovery`.

## Gotchas

- Unauthenticated crawls only see the public surface — most interesting app logic sits
  behind auth; plan an authenticated crawl pass explicitly if credentials are provided.
- Crawlers will follow external links and third-party resources unless scoped — constrain
  with the tool's whitelist/scope flag or filter output afterward; never scan what the
  crawl incidentally touched outside `scope.txt`.
- High crawl concurrency against a small app can look like (and function as) a denial-of-
  service — start conservative per `opsec-discipline`, especially on non-CDN-fronted origins.
- Single-page apps (SPA) often render most content client-side — a plain HTML crawler will
  return almost nothing; use `katana -jc` or a headless-browser-based crawl instead.
