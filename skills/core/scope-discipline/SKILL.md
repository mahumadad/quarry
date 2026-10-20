---
name: scope-discipline
description: >
  Scope validation rules for pentest engagements: how to confirm a target is in scope
  before touching it, how to handle out-of-scope discoveries, and how to handle scope
  ambiguity. Use before ANY recon, scanning, or testing action against a target, and
  whenever a new host/domain/IP/asset is discovered mid-engagement. This is a gating
  skill, not a recon technique — every other skill depends on it.
metadata:
  type: core
  phase: scoped
  tools: [whois, dig, curl]
depends_on: []
feeds_into: [engagement-flow, passive-recon, active-recon, port-scan, web-crawling, api-discovery, cloud-recon]
---

## Signals

- Before the first action against any new host, domain, IP range, or cloud asset.
- A recon skill discovers a new subdomain, IP, CNAME target, or cloud bucket not in the original scope list.
- The client asks to "just check this one more thing" mid-engagement.
- Ambiguity about whether a shared/third-party asset (CDN, SaaS, partner API) is testable.

## Prerequisites

- Written authorization: a signed statement of work, rules of engagement (RoE) document, or
  explicit written client sign-off naming the exact assets, IP ranges, and testing windows.
  Verbal "go ahead" is not sufficient for anything beyond passive OSINT.

## Methodology

1. Before engagement start, build an explicit scope list from the RoE — domains, subdomains,
   CIDR ranges, cloud account IDs, and anything explicitly excluded. Keep it as a literal file
   (e.g. `scope.txt` with one entry per line) that every other skill reads from.
2. For every new target before touching it, validate membership:
   ```bash
   # domain/subdomain membership
   grep -E "(^|\.)example\.com$" scope.txt

   # IP in CIDR range
   python3 -c "import ipaddress; print(ipaddress.ip_address('1.2.3.4') in ipaddress.ip_network('1.2.3.0/24'))"

   # or with a CLI tool
   prips 1.2.3.0/24 | grep 1.2.3.4
   ```
3. For discovered assets with ambiguous ownership (shared hosting, CDN edge, SaaS subdomain),
   confirm actual ownership before scanning:
   ```bash
   whois example.com | grep -i "org\|registrant"
   dig +short CNAME sub.example.com      # does it point to a third party (e.g. *.herokuapp.com, *.cloudfront.net)?
   curl -sI https://sub.example.com | grep -i "server\|x-served-by"
   ```
   A CNAME to infra not owned by the client (Shopify, AWS CloudFront, Cloudflare Pages, etc.)
   is presumptively out of scope unless the RoE explicitly covers shared/cloud infrastructure
   testing — stop and ask.
4. Log every scope decision, including exclusions, in a scope-log (timestamp, asset, decision,
   reasoning). This is evidence for the final report and for covering yourself if questioned later.
5. When a scan/tool returns results outside the defined ranges (common with wildcard subdomain
   brute force, ASN-based IP discovery, or Shodan/Censys queries), filter immediately:
   ```bash
   subfinder -d example.com -silent | grep -E "\.example\.com$" > inscope-subs.txt
   ```
   Do not hunt or exploit against the filtered-out set, even "just to see."

## Tooling

`whois`, `dig`/`host`, `curl -I`, `ipaddress` (Python stdlib), `prips`, `grep`/`comm` for set
filtering against `scope.txt`.

## Validation gate

Before any active action against a target:
- [ ] Target appears in `scope.txt` (domain suffix match, or IP within an authorized CIDR).
- [ ] If the target resolves/CNAMEs to third-party infrastructure, ownership and RoE coverage
      confirmed explicitly — not assumed.
- [ ] If in doubt, the ambiguity has been raised with the human operator, not resolved silently.

## Gotchas

- Wildcard DNS and subdomain brute force will return hosts the client doesn't own (dev
  environments on third-party PaaS, abandoned subdomains pointing to expired cloud resources,
  partner integrations). Scope match on the domain name is necessary but not sufficient —
  check what actually answers.
- "In scope" at engagement start doesn't mean "in scope forever" — RoE windows, IP allowlisting
  requirements, and excluded assets can change; re-check scope.txt if the engagement spans
  more than a few days.
- Never widen scope based on verbal requests mid-engagement ("can you also check our other
  site?") without written confirmation added to the RoE — redirect to `engagement-flow`'s
  escalation step.
- A target that was in scope and is now unreachable/decommissioned is not an invitation to
  pivot to whatever replaced it without re-confirming that the replacement is also in scope.
