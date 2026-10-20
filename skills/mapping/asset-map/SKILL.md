---
name: asset-map
description: >
  Build and maintain a complete asset inventory for the current engagement:
  domains, subdomains, IPs/CIDR ranges, open ports, running services, web
  applications, APIs, and cloud resources. Cross-references all recon tool
  output into one structured, deduplicated inventory that every later phase
  (trust-map, identity-map, chain-analysis) reads from.
  Use when starting a new engagement, when new scope is added mid-engagement,
  or when recon output needs to be reconciled into a single source of truth.
  Do NOT use for analyzing trust relationships between assets — use trust-map.
  Do NOT use for auth/identity model details — use identity-map.
metadata:
  type: mapping
  phase: mapped
  tools: [subfinder, amass, dnsx, httpx, naabu, nmap, masscan, nuclei, katana, gowitness, cloud_enum]
depends_on: []
feeds_into: [trust-map, identity-map, state-map, capability-map, chain-analysis]
chains_with: []
---

## Signals

- Starting a new engagement with only a root domain, CIDR, or company name as scope.
- Scope was expanded (new subsidiary, new domain, new cloud account) mid-engagement.
- Recon tool outputs exist in separate files (subfinder.txt, httpx.json, nmap/*.xml) but
  nothing has reconciled them into one inventory yet.
- A later skill (trust-map, chain-analysis) asks "what else talks to this host?" and there
  is no single place to answer that.

## Prerequisites

- Signed scope/rules-of-engagement document naming in-scope domains, IP ranges, and any
  explicitly excluded assets (production payment systems, third-party SaaS, etc.).
- Read/execute access to standard recon tooling (see `tools` above). If a tool is missing,
  note the gap rather than silently skipping that asset class.

## Methodology

1. **Seed from scope.** Extract every root domain, CIDR block, ASN, and named cloud
   account/org from the RoE. Record each as a top-level entry — this is your allow-list;
   anything discovered outside it goes to an "out of scope — needs sponsor confirmation"
   bucket, never directly into the active inventory.

2. **Subdomain enumeration (passive then active).**
   - Passive: `subfinder -d <domain> -all`, `amass enum -passive -d <domain>`, certificate
     transparency (crt.sh), DNS aggregators.
   - Active (only if RoE permits brute force): `dnsx -d <domain> -w <wordlist>`, permutation
     tools (dnsgen, altdns) fed back through `dnsx`.
   - Resolve everything with `dnsx -resp -a -aaaa -cname -ptr` and keep the full record set,
     not just the A record — CNAME chains reveal cloud providers (e.g. `*.s3.amazonaws.com`,
     `*.cloudfront.net`, `*.azurewebsites.net`) that matter for trust-map later.

3. **Port/service discovery.** `naabu -l hosts.txt -top-ports 1000` for breadth, `nmap -sV
   -sC -p <findings>` for the subset worth fingerprinting in depth. Record: host, port,
   protocol, service name, version string, TLS cert CN/SAN (certs frequently leak internal
   hostnames — feed those back into step 2).

4. **Web app / API surface.** `httpx -l hosts.txt -title -tech-detect -status-code
   -content-length -follow-redirects` on every host with an open HTTP(S) port. Crawl with
   `katana` to enumerate endpoints and JS-sourced API paths. Screenshot with `gowitness` for
   fast visual triage of what each host actually is. Separate "web app" from "API" from
   "static asset host" — they get different follow-up treatment.

5. **Cloud resource discovery.** For each cloud provider implied by CNAMEs, TLS certs, or
   RoE: enumerate public buckets/blobs (`cloud_enum`, provider-specific tools), check for
   exposed metadata endpoints reachable from any discovered SSRF-prone service, and note
   which cloud account each resource belongs to (needed by chain-ssrf-to-cloud later).

6. **Cross-reference and dedupe.** Merge all of the above into one record per asset, keyed
   by canonical identifier (IP for infra, FQDN for virtual hosts, ARN/resource-ID for cloud).
   An asset with five different discovery sources is still one row, with all five sources
   listed as provenance — this provenance list is what later validation gates (Gate 2:
   Reachability) will ask you to produce.

7. **Classify and prioritize.** Tag each asset: `prod` / `staging` / `dev` / `unknown`,
   `internet-facing` / `internal-only` (as far as observable), and a rough tech stack. Flag
   anything that looks EOL, unpatched, or default-configured for priority follow-up.

## Validation gate

Before handing the inventory to trust-map/identity-map/chain-analysis, confirm:
- Every asset traces to an in-scope seed (domain, CIDR, or explicit RoE inclusion) — if not,
  it sits in the out-of-scope bucket until the sponsor confirms it.
- Every asset has at least one piece of evidence (tool output, timestamp) backing its entry
  — no asset is in the inventory "from memory" or inference alone.
- No duplicate rows for the same underlying host/resource under different discovery paths.

## Gotchas

- Wildcard DNS and CDN edge IPs will make naive port scans look identical across hundreds of
  "hosts" — always resolve through to the origin where possible before treating two
  hostnames as two distinct assets.
- Subdomain takeover candidates (dangling CNAME to an unclaimed cloud resource) are an asset-
  map finding, not a chain finding — flag them here, chain them later if they enable
  something.
- Rate-limit active enumeration against anything flagged `prod` — a scope note doesn't
  override a client's uptime requirements; check the RoE for allowed testing windows.
- Cloud resources discovered via a CNAME often belong to a *different* AWS/Azure/GCP account
  than the one named in the RoE (e.g. a vendor's shared CDN tenant) — do not assume ownership
  without confirming; mark it "third-party-hosted, needs scope confirmation" instead.
- A host can be in-scope by IP but out-of-scope by hostname (or vice versa) when shared
  hosting is involved — record both and flag the ambiguity rather than resolving it yourself.
