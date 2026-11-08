# Harness Patterns for AI-Assisted Pentesting

Reference document consolidating patterns from:
- Provos — "Finding Zero-Days with Any Model" (IronCurtain workflow)
- Helton & Basden — "Harness Engineering Workshop"
- Arcanum-Sec — SpikeStrip (defensive decoys)
- Sectiv — Burp Suite AI review with multi-provider support

## Core Principle

> "Model capability is not research capability." — Helton

An LLM without a harness produces generic, unverified output. A harness
provides: target context, deterministic tools, authorization boundaries,
durable state, and validation methods. Quarry IS this harness.

## Pattern 1: Hypothesis → Validate (Provos)

Static analysis generates hypotheses; only execution confirms them.

1. **Hypothesize** — identify potential vulnerability from code/config/version
2. **Build harness** — create minimal reproduction environment
3. **Validate** — execute and observe (sanitizer output, crash, behavior change)
4. **Classify** — Demonstrated / Inferred / Unproven

Quarry mapping:
- Hypothesis = Lead (engine/leads.py)
- Harness = PoC (engine/poc_gen.py)
- Validate = Browser verify (engine/browser_verify.py) or tool output
- Classify = Evidence tags in findings

## Pattern 2: Harness Tiering (Provos)

Escalate validation complexity only as needed:

| Tier | Scope | Example | Quarry equivalent |
|------|-------|---------|-------------------|
| T1 | Single function | Focused fuzzer for one parser | Skill-level test (hunt/sqli on one endpoint) |
| T2 | Multi-component | Integration test across services | Chain analysis (engine/chain_engine.py) |
| T3 | Full E2E | QEMU VM, full protocol stack | Browser verification + manual operator validation |

## Pattern 3: Append-Only Journal (Provos / IronCurtain)

Every agent action logged to an append-only journal that:
- Coordinates between specialist agents
- Provides audit trail
- Enables state reconstruction after context reset

Quarry equivalents:
- engine/custody.py — hash-chained evidence log
- engine/episodic.py — engagement episode memory
- .pentest-state/brain.json — capability/vector state

## Pattern 4: Lead ≠ Finding (Helton)

Agent output is a **lead**, not a **finding**. The researcher (or engine)
must validate before promoting to finding status.

Quarry implementation:
- Leads (engine/leads.py) — open vectors blocking closeout
- Findings (engine/findings.py) — validated with evidence tags
- Evidence gate: Demonstrated requires PoC; Inferred requires partial evidence

## Pattern 5: Multi-Provider Second Opinion (Provos + Sectiv)

Different models have different blind spots. Querying multiple providers
reduces false negatives:

- **Primary** (Claude/Opus): orchestration, deep reasoning, exploitation
- **Brainstorm** (DeepSeek): vector ideation, cheap and fast
- **Long context** (Kimi 128k): large codebase analysis, CVE deep-dives
- **Verification** (GLM): independent second opinion on findings
- **Local** (Ollama): offline work, sensitive targets

Via LiteLLM gateway (engine/llm_gateway.py), all behind bidirectional
redaction (engine/redaction.py).

## Pattern 6: Decoy Awareness (SpikeStrip)

Defenders plant AI-targeted decoys in web content:
- Fabricated routes with real CVE IDs
- Workflow derailment instructions in HTML/JS comments
- Mathematical impossibility tasks
- Hex-keyed tracking markers

Quarry countermeasure: engine/decoy_detector.py scans content for these
patterns and flags affected findings. Comments with instruction-like
content adjacent to 12+ char hex keys are high-confidence decoys.

## Pattern 7: Privacy-First Provider Integration (Sectiv)

When sending engagement data to external providers:
1. Redact all authentication tokens, cookies, API keys
2. Anonymize IP addresses (replace with HOST_N placeholders)
3. Strip JWTs entirely
4. Never send raw request/response pairs — summarize first
5. Log what was sent and to whom (custody chain)

Quarry implementation: redact_for_provider() in engine/redaction.py
applied automatically by engine/llm_gateway.py before every API call.

## Pattern 8: CVE Intelligence Fusion (Zero Wire + NVD + KEV + EPSS)

Layer multiple intelligence sources for CVE prioritization:

| Source | Signal | Quarry integration |
|--------|--------|--------------------|
| NVD | Base score, vector, description | engine/cve_feeds.py query_nvd() |
| CISA KEV | Active exploitation confirmed | engine/cve_feeds.py query_kev() |
| FIRST EPSS | Exploitation probability score | engine/cve_feeds.py query_epss() |
| CF Zero Wire | Critical vuln briefings, AI prompts | engine/cve_feeds.py query_zero_wire() |
| LLM CVE dive | Preconditions, verify steps | engine/llm_gateway.py cve_deepdive() |

A CVE in KEV + Zero Wire + high EPSS = automatic Fire priority.
