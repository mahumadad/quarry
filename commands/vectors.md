---
name: quarry:vectors
description: Query alternative providers to identify unexplored attack vectors
argument-hint: "[--provider <name>] [--type <brainstorm|opinion|cve>]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:vectors [--provider <name>] [--type <brainstorm|opinion|cve>]

Queries an alternative LLM (DeepSeek, GLM, Kimi, OpenRouter, Ollama)
to get a second opinion on which attack vectors remain unexplored in
the current engagement.

## Precondition

- Active engagement (`.pentest-state/engagement.json` exists).
- At least one provider configured in `.pentest-state/providers.json`.
  If no providers exist, guide the operator to configure one:

  ```json
  {
    "providers": {
      "deepseek": {"api_key": "sk-...", "default_model": "deepseek-chat"}
    },
    "routing": {
      "vector_brainstorm": "deepseek",
      "fallback": "deepseek"
    }
  }
  ```

## Flow

### 1. Load engagement state

Read from the Brain:
- `brain.capabilities` — what the attacker can do now
- `brain.exhausted_vectors` — what was tried and failed
- `brain.active_vectors` — what is in progress

Read from `decision_engine.py`:
- Detected stack (AppProfile)
- Already executed skills

Read from `findings.json`:
- Findings summary by class and severity
- Findings tagged `Inferred` that could benefit from validation

Read from `coverage.json`:
- Coverage gaps (untested cells)

### 2. Build contextualized prompt

Use `LLMGateway.vector_brainstorm()` which sends:
- Technology stack
- Exhausted vectors
- Gained capabilities
- Findings summary

The prompt asks for untried vectors, prioritized by success
probability. Format: JSON array with `vector`, `target`, `rationale`,
`priority`, `vuln_class`.

### 3. Parse response and register leads

Each suggested vector is registered as a Lead in `engine/leads.py`:
- `source`: `"llm_gateway:{provider}:{model}"`
- `priority`: the one suggested by the provider
- `status`: `open`
- `vuln_class_hint`: the suggested class

### 4. Filter duplicates

Before registering, check against:
- Already existing leads (by similar title)
- Brain's exhausted vectors (already attempted)
- Coverage cells already marked `tested_clean`

### 5. Present to operator

Show a table with the suggested vectors, indicating:
- Which are new (not in exhausted or in leads)
- Which confirm coverage tracker gaps
- Which the operator should prioritize

Do not execute anything automatically — only register leads and recommend.

## Subcommands

### `/quarry:vectors --type opinion --finding <id>`

Requests a second opinion on a specific finding using
`LLMGateway.second_opinion()`. Useful for `Inferred` findings where
external assessment validation is desired.

### `/quarry:vectors --type cve --service <name> --version <ver>`

CVE deep-dive for a service using `LLMGateway.cve_deepdive()`. Useful
when a version is detected and you want to know which CVEs apply
before attempting exploitation.

### `/quarry:vectors --provider <name>`

Forces a specific provider instead of the configured routing.

## Anti-fabrication

- Vectors suggested by the LLM are **leads, not findings**.
- They are not registered as findings until verified.
- The source tag `llm_gateway:*` makes the origin clear.
- Bidirectional redaction (`redact_for_provider`) is applied BEFORE
  sending to the provider — no tokens, cookies, or real target IPs
  are leaked.
