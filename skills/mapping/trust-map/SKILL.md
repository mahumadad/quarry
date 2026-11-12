---
name: trust-map
description: >
  Map trust boundaries across the engagement: where trust transitions happen
  (network perimeter, auth boundary, process/container boundary, org/tenant
  boundary), which components trust which inputs from which others, and
  where network segmentation claims do or don't hold up in practice.
  Use after asset-map has produced an inventory, before chain-analysis, to
  identify which boundary crossings are worth testing as pivot points.
  Do NOT use for enumerating roles/permissions — use identity-map.
  Do NOT use for proposing specific exploit chains — use chain-analysis.
metadata:
  type: mapping
  phase: mapped
  tools: [nmap, traceroute, curl, openssl, jwt_tool, burp, wireshark, cloud_iam_query_tools]
depends_on: [asset-map]
feeds_into: [chain-analysis, chain-ssrf-to-cloud, chain-web-to-rce]
chains_with: []
---

## Signals

- asset-map is complete and you need to know which assets can reach which others, and on
  what trust basis (shared network, shared credential, shared parent/child auth token).
- A component accepts input from another component and you need to know whether that input
  is treated as trusted (internal) or untrusted (external) by the receiver.
- Segmentation documentation (network diagrams, firewall rules, VPC layout) exists but hasn't
  been verified against what's actually reachable.
- Preparing for chain-analysis — pivot graphs are built on top of trust-map output, not
  the other way around.

## Prerequisites

- Completed asset-map inventory with service/port data per host.
- Any architecture docs, network diagrams, or IAM policy exports the client provided (treated
  as a *hypothesis* to verify, never as ground truth — see Sources of truth in project rules).
- Ability to test reachability from each foothold the engagement has established so far
  (external, internal network, compromised host, authenticated session at each privilege tier).

## Methodology

1. **Enumerate claimed boundaries.** From client docs and asset-map tags (`internet-facing`
   vs `internal-only`, `prod` vs `staging`), list every boundary someone believes exists:
   network segments (DMZ vs internal VLAN), auth boundaries (anonymous vs authenticated vs
   admin), tenancy boundaries (multi-tenant SaaS isolation), process boundaries (sandboxed
   worker vs host), and org boundaries (your target vs a third-party integration).

2. **Test each boundary from each foothold.** For every (foothold, target) pair that should
   be blocked per the claimed boundary, actually attempt the connection/request and record
   the real result — reachable, blocked, blocked-but-service-fingerprintable (e.g. a TCP RST
   still confirms the port exists). Use `nmap`/`curl`/`traceroute` from each foothold, not
   just from the attacker's starting point — a boundary that holds from the internet can be
   wide open from a compromised internal host.

3. **Map trust direction, not just connectivity.** Connectivity ≠ trust. For each reachable
   edge, determine: does the receiving component treat this sender's input as trusted
   (skips validation, auto-elevates privilege, assumes authenticity) or untrusted (revalidates
   everything)? Look for internal APIs with no auth because "only internal services call this,"
   service-to-service calls using static shared secrets, and signed-but-unverified tokens
   passed between services.

4. **Map auth boundary transitions specifically.** Where does a request stop being anonymous
   and start being authenticated? Where does session-scoped identity get translated into a
   backend-trusted identity (e.g. a reverse proxy that adds an `X-User-Id` header the backend
   trusts blindly)? These header-injection-style trust handoffs are a recurring chain source —
   flag every point where one component's output becomes another component's trusted input
   without independent verification.

5. **Map tenancy/org boundaries.** For multi-tenant systems, identify every place a
   tenant/account identifier is used to scope a query, a cache key, a file path, or a queue
   name. Each one is a candidate IDOR/cross-tenant boundary — note it here, test it as IDOR
   findings, chain it later via chain-idor-to-mass-data.

6. **Diagram the result.** Produce a boundary graph: nodes are components/zones, edges are
   (direction, protocol, auth-basis, verified-trust-level). Mark each claimed boundary as
   HOLDS / PARTIALLY-HOLDS / DOES-NOT-HOLD with the evidence (command + output) for each
   verdict.

## Validation gate

- Every boundary verdict has a reproducible test (command run, response observed) — no
  verdict is based on a diagram or a doc alone.
- Every "trusted input" claim about a component is backed by an observed behavior (e.g. the
  component skipped auth when the header was present) not an assumption from naming
  conventions.
- Boundary crossings that chain-analysis will need (anything DOES-NOT-HOLD or
  PARTIALLY-HOLDS) are flagged with enough detail (exact header, exact endpoint, exact
  condition) to be reused without re-deriving it.

## Gotchas

- "Internal-only" is a network claim, not a trust claim — a service with no auth that is
  reachable from one compromised internal host is a full boundary failure even if the
  internet can't reach it directly.
- Load balancers, API gateways, and reverse proxies often silently re-trust requests they
  relay — test the backend directly (when reachable) to see if it enforces anything the
  gateway was assumed to enforce.
- Cloud security groups and on-prem firewalls drift from their documented state constantly —
  always verify, never cite the doc as the finding.
- A boundary that holds for one protocol (HTTP blocked) may not hold for another (the same
  host answers on a management port, a metrics endpoint, or a debug port the diagram omits).
- Don't test production boundary crossings in ways that cause outages (e.g. aggressive
  segmentation probing that trips IPS/WAF account lockouts) — confirm allowed testing
  windows and techniques against the RoE first.
