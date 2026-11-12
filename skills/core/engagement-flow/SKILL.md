---
name: engagement-flow
description: >
  Overall pentest engagement methodology: phases, gates between phases, and when to
  escalate to the human operator. Use at the start of any engagement to orient, and
  whenever it's unclear what phase the engagement is in or whether it's safe to move
  to the next one. Not a recon/scanning skill itself — it routes to the skill that
  owns the current phase.
metadata:
  type: core
  phase: scoped
  tools: []
depends_on: [scope-discipline]
feeds_into: [passive-recon, active-recon, osint]
---

## Signals

- Starting a new engagement ("start a pentest on X", "begin the assessment").
- Unclear which phase the engagement is currently in.
- About to transition phases (e.g. recon feels "done", moving to active scanning or exploitation).
- Any point where impact, scope, or authorization is ambiguous — escalate, don't guess.

## Prerequisites

- A signed/confirmed scope document or explicit written authorization (see `scope-discipline`).
  If this does not exist, stop — do not proceed to any other skill.

## Phase state machine

```
SCOPED → RECON → MAPPED → HUNTING → CHAINING → VALIDATING → REPORTING
  │         │        │         │          │           │           │
  │         │        │         │          │           │           └─ final report, retest plan
  │         │        │         │          │           └─ confirm impact, reproduce clean PoC
  │         │        │         │          └─ combine findings into exploit chains
  │         │        │         └─ hunt for vulns against mapped attack surface
  │         │        └─ attack surface fully enumerated (hosts, ports, services, apps, APIs)
  │         └─ passive + active recon complete
  └─ scope confirmed, rules of engagement signed, authorization letter in hand
```

Each phase is owned by a cluster of skills:
- **SCOPED**: `scope-discipline`, `opsec-discipline` (set rate limits/UA policy before anything fires).
- **RECON**: all 15 skills under `skills/recon/*` — passive first, then active, in roughly this order:
  `passive-recon` → `dns-enumeration` → `subdomain-discovery` → `osint`/`github-dorking`/`email-harvesting` (parallel, passive) → `active-recon` → `port-scan` → `service-enumeration` → `tech-stack-fingerprint`/`waf-fingerprint` → `web-crawling` → `js-analysis` → `api-discovery` → `cloud-recon`.
- **MAPPED**: gate check — attack surface inventory exists (hosts, ports, services, endpoints, params, cloud assets) before hunting begins.
- **HUNTING**: vuln-class-specific skills (not in this batch) consume the MAPPED inventory.
- **CHAINING**: combine individually low-severity findings into a demonstrated chain (see `finding-discipline` for what "demonstrated" requires).
- **VALIDATING**: re-run each PoC clean, confirm it isn't a fluke, confirm it's inside scope.
- **REPORTING**: write up with `finding-discipline` evidence tiers.

## Methodology

1. Confirm phase gate before starting work: ask "what artifact proves the previous phase is done?" If you can't name one, you're not actually in the next phase yet.
2. At RECON → MAPPED: produce a single inventory (hosts.txt, ports.csv, endpoints.txt, apps.md) before any hunting skill runs. Hunting against a partial inventory produces partial coverage and false confidence.
3. At MAPPED → HUNTING: re-check scope-discipline against the inventory. Recon frequently discovers hosts/subdomains/cloud assets that are *not* in the original scope (third-party CDNs, SaaS tenants, dev subdomains owned by someone else). Flag and exclude these — do not test them even if they resolve.
4. At HUNTING → CHAINING: do not report a finding until it clears `finding-discipline`'s evidence bar.
5. At any phase: if an action would affect availability (intensive scans, fuzzing that could trip WAF bans or rate-limit the client's real users, anything destructive), pause and confirm with the human operator before proceeding — this is an escalation point, not a judgment call to make alone.
6. REPORTING: hand off to report-writing skills (not in this batch) using the Demonstrated/Inferred/Unproven tags from `finding-discipline`.

## Validation gate

Before declaring a phase complete, confirm:
- [ ] An artifact (file/doc) exists that another operator could pick up and continue from.
- [ ] Scope was re-validated against anything new discovered this phase.
- [ ] No irreversible or availability-impacting action was taken without explicit sign-off.

## Gotchas

- Treating recon as "done" because it ran once — recon is iterative; subdomain discovery often needs a second pass after DNS enumeration reveals new naming patterns.
- Skipping the MAPPED gate and hunting opportunistically against whatever host was scanned last — leads to uneven coverage and missed scope violations.
- Escalating too late: if you're unsure whether something is in scope or whether an action could cause damage, that uncertainty itself is the signal to stop and ask, not a reason to proceed cautiously and see what happens.
