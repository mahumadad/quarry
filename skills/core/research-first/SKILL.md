---
name: research-first
description: >
  Mandatory pre-hunt intelligence gathering from knowledge base.
  Before writing ANY payload, consult references/vuln-classes/{class}.md
  and references/chains/ for known patterns.
metadata:
  category: core
  phase: [RECON, MAPPED, HUNTING]
  priority: P0
  depends_on: [scope-discipline, engagement-flow]
  feeds_into: [hunt/*, chain/*]
  chains_with: []
---

# Research-First Discipline

**Rule: NO payload leaves your hands without consulting the knowledge base.**

## Why This Exists

AI agents waste 40-60% of tool calls reinventing known techniques. The
knowledge base (`references/vuln-classes/` and `references/chains/`)
contains field-tested payloads, bypass patterns, and chain recipes that
cover the common cases. Skipping this step means slower engagements,
weaker findings, and missed chains.

## Protocol

### Before Every Hunt

1. **Identify the vuln class** you're about to test (e.g., `xss`, `sqli`,
   `ssrf`).

2. **Read the cheatsheet**: `references/vuln-classes/{class}.md`
   - Detection payloads (what to try first)
   - Bypass patterns per WAF/framework
   - Validation criteria (when is it real)
   - Common mistakes for this class

3. **Read chain patterns**: `references/chains/chain-patterns.md`
   - What chains from this vuln class
   - What chains INTO this vuln class
   - Known escalation paths

4. **Check AppProfile** (engine/app_profile.py):
   - What tech stack? → Use framework-specific payloads
   - What WAF/CDN? → Use known bypass patterns
   - What auth mechanism? → Adapt to session handling

5. **Check Brain** (engine/brain.py):
   - What capabilities do we already have? → Skip redundant probes
   - What was already tried? → Don't repeat exhausted vectors
   - What vectors are active? → Coordinate, don't collide

### Payload Selection Order

```
1. Known-good payload from cheatsheet for this tech stack
2. Variant of known-good adapted to observed WAF/encoding
3. Novel payload (only after 1 and 2 exhausted)
```

Never start with novel payloads. The cheatsheet payloads have been field-
tested; novel payloads haven't.

### After Every Finding

1. **Record the working payload** back to the Brain
2. **Note the bypass** if any WAF/filter was circumvented
3. **Check chain anchors** in the hunt skill's Chain Anchors section
4. **Update capabilities** in the Brain for chain engine

## Validation Gate

Before any hunt agent fires its first payload:

```
□ vuln-class cheatsheet loaded? → if not, load it
□ AppProfile consulted? → if not, read it
□ Brain checked for prior work? → if not, check it
□ Payload from cheatsheet, not invented? → if novel, justify why
```

Failing this gate means the agent skipped research. The engagement
controller SHOULD reject the action and force a research pass.

## Gotchas

- Cheatsheets are starting points, not exhaustive. If the target uses
  an unusual framework, the agent MUST adapt — but start from the
  closest known pattern.
- Bypass patterns age fast. If a known bypass fails, mark it exhausted
  in the Brain and try the next one.
- Don't cargo-cult payloads. A cheatsheet payload for PHP won't work
  on Node.js SSTI. Match the payload to the confirmed tech stack.
