---
name: capability-map
description: >
  Map what each component can technically do once reached: file read/write,
  outbound network requests (SSRF surface), command/code execution paths,
  database query execution, email/notification sending, and payment
  processing. This is the "blast radius" map — for every asset and every
  identity, what is the ceiling of damage if that asset/identity is fully
  compromised. Built from asset-map + trust-map + identity-map + state-map.
  Use before chain-analysis to answer "if I own this, what can I actually
  do with it" for each node in the pivot graph.
  Do NOT use this to enumerate assets or trust edges themselves — use
  asset-map/trust-map for that; this skill answers "capability," not
  "reachability."
metadata:
  type: mapping
  phase: mapped
  tools: [burp, curl, nmap, cloud_iam_query_tools, source_review, ssrf_canary_tools]
depends_on: [asset-map, trust-map, identity-map, state-map]
feeds_into: [chain-analysis, chain-web-to-rce, chain-ssrf-to-cloud]
chains_with: [chain-web-to-rce, chain-ssrf-to-cloud]
---

## Signals

- All four prior mapping skills are done and you need a single answer, per component, to
  "what's the worst this component can be made to do."
- About to run chain-analysis and need capability data for each node in the pivot graph —
  chain-analysis consumes this map directly.
- A component makes outbound requests (webhooks, URL preview, image fetch, PDF generation,
  import-from-URL) and you need to scope the SSRF blast radius before testing it.
- A component executes code/commands/queries on behalf of input and you need to know the
  execution context (user it runs as, sandbox boundaries, filesystem access).

## Prerequisites

- Completed asset-map, trust-map, identity-map, and state-map for the engagement.
- Source code access where available (greatly increases accuracy over black-box inference);
  black-box capability inference is valid but should be marked lower-confidence.

## Methodology

1. **For every component, enumerate its outbound capabilities.**
   - *Network*: does it make outbound HTTP(S) requests based on user input (webhooks, URL
     fetchers, link previews, SSO metadata fetch, PDF/screenshot generators)? Record the
     exact parameter that controls the destination and whether scheme/host/port is
     restricted.
   - *Filesystem*: does it read/write files based on user input (uploads, exports, template
     rendering, log paths)? Record the user context it runs as and whether path construction
     uses user-controlled segments.
   - *Execution*: does it invoke a shell, subprocess, template engine with code execution
     (SSTI-capable), deserializer, or eval-equivalent? Record the exact sink and what reaches
     it.
   - *Database*: does it build and execute queries from user input? Record ORM usage vs raw
     query construction, and the DB user's actual grants (not the app's intended grants).
   - *Messaging*: can user input trigger an outbound email, SMS, push notification, or
     webhook to a third party? This is both an abuse vector (spam/phishing relay) and a
     potential verification/notification bypass surface.
   - *Payment*: does this component touch payment initiation, refunds, balance adjustment,
     or financial reconciliation? Treat any such component as high-blast-radius by default.

2. **Record execution context, not just the action.** "Can execute shell commands" matters
   differently if it runs as an unprivileged container user with no network egress than if it
   runs as root with full outbound access. Capture: OS user, container vs host, network
   egress rules (cross-reference trust-map), and any sandbox/seccomp/AppArmor constraints
   observed or documented.

3. **Tie capability back to identity.** For each capability, note which identity tier
   (from identity-map) is required to trigger it: anonymous, authenticated-low-priv,
   authenticated-admin, service-account-only. A dangerous capability reachable only by an
   already-admin identity is a much smaller finding than the same capability reachable
   anonymously.

4. **Flag SSRF-capable components explicitly.** Any outbound-request capability is a
   candidate input to chain-ssrf-to-cloud. For each, test (where RoE permits) whether it can
   reach link-local/metadata addresses (`169.254.169.254`, `metadata.google.internal`),
   internal-only hosts identified in trust-map, or alternate schemes (`file://`, `gopher://`,
   `dict://`) that extend impact beyond plain HTTP fetch.

5. **Flag RCE-adjacent components explicitly.** Template engines, deserializers, dynamic
   code loaders, image/document converters that shell out to external binaries (ImageMagick,
   LibreOffice, pandoc) — these are recurring RCE sources and are the direct input to
   chain-web-to-rce.

6. **Build the capability matrix.** Rows = components, columns = capability classes
   (network-out, fs-rw, exec, db-query, notify, payment). Cell = NONE / LIMITED(describe) /
   FULL, with the evidence link. This matrix is what chain-analysis's matrix mode iterates
   over.

## Validation gate

- Every FULL or LIMITED capability cell has supporting evidence (code reference, or an
  observed test within RoE) — no cell is populated from assumption.
- Every SSRF-capable and RCE-adjacent component is explicitly flagged for hand-off to its
  respective chain skill.
- Capability-to-identity mapping is complete for every FULL/LIMITED cell — "who can trigger
  this" is never left blank.

## Gotchas

- A capability doesn't need to be *intended* to count — a PDF export feature that shells out
  to `wkhtmltopdf` on attacker-influenced HTML has command-execution-adjacent capability
  whether or not anyone designed it that way.
- Outbound network capability restricted to an allow-list is only as good as the allow-list
  implementation — check whether it's enforced by string match (bypassable via redirects,
  DNS rebinding, alternate IP encodings) or by actual network policy.
- "Runs in a sandbox" claims need verification — a container without seccomp/user-namespace
  restrictions is not meaningfully sandboxed against host-level impact if there's a kernel or
  Docker-socket escape path available.
- Don't conflate "has the capability" with "is vulnerable" — this map records ceiling of
  action, not confirmed exploitability; confirmed exploitability is chain-analysis's and
  finding-validation's job.
- Capability discovered via source review needs a black-box sanity check where RoE allows it
  — code can be dead, feature-flagged off, or superseded by a newer code path in production.
