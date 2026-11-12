---
name: llm-fuzzing
description: >
  Automated adversarial fuzzing of LLM-powered features with garak and prompt-fuzzing
  tools. Use when api-discovery identifies AI features (chatbots, copilots, RAG search,
  agentic tools) and manual prompt-injection probing needs breadth: run garak probe
  suites (jailbreaks, encoding attacks, data-leak probes), LLMFuzzer-style mutation
  campaigns, and encoding/blind prompt-injection sweeps, then triage hits manually.
  Keywords: garak, LLM fuzzing, prompt injection automation, jailbreak probes,
  DAN, encoding attacks, payload split, adversarial suffix, LLMFuzzer, PyRIT.
  Do NOT use for targeted exploitation of an already-confirmed injection (that is
  prompt-injection / indirect-injection territory) — this is breadth automation.
metadata:
  type: ai-security
  phase: hunting
  cwe: [CWE-1427]
  mitre_attack: [AML.T0051, AML.T0054]
  tools: [garak, pyrit, curl]
depends_on: [ai-agent-recon, api-discovery]
feeds_into: [prompt-injection, indirect-injection, finding-validation]
chains_with: [prompt-injection, exfiltration-via-ai, tool-abuse]
---

## Purpose

Manual prompt-injection testing is deep but narrow — an operator tries dozens
of phrasings; garak tries thousands across probe families in one run. This
skill adds the automation breadth layer to the ai-security skills: run the
probe suites, then apply the plugin's normal evidence bar to whatever they
surface.

## Methodology

1. **Confirm the target shape from ai-agent-recon:** provider-backed API or
   in-app feature? Direct model endpoint, RAG pipeline, or agent with tools?
   Probe selection depends on it (agentic targets get tool-abuse probes;
   RAG gets data-leak/poisoning probes).

2. **Run garak against the endpoint:**
   ```bash
   # REST targets use the rest generator with a request template
   garak --model_type rest -G rest-template.json \
     --probes encoding,dan,jailbreak,leakreplay,promptinject \
     --report_prefix engagement-ai
   ```
   Verify `garak --help` flags before first use (CLI anti-hallucination rule).
   Scope the probe list deliberately — a full `all` run is hours of traffic
   and loud; pick families by what ai-agent-recon found.

3. **Probe families and when:**
   - `encoding` — base64/rot13/hex-wrapped injections (weak input filters).
   - `dan`, `jailbreak` — persona/override attacks on system prompts.
   - `leakreplay`, `xss`, `malwaregen` — training-data echo and unsafe output.
   - `promptinject` — rogue-string/ignore-previous families.
   - `latentinjection` — indirect vectors when the app consumes documents/web.
   - For agentic apps: PyRIT or hand-rolled campaigns against tool-calling
     behavior (garak's agent support is thin — manual tool-abuse skill leads).

4. **Triage hits with the brocards.** Garak detectors are heuristic — a
   "hit" is a LEAD (B3: the scanner is a witness, not a judge). Every
   promoted hit gets manual reproduction: same prompt via the app's real UI/
   API, effect observed, impact named (B4). The garak report file is cited as
   detection record, never as finding evidence.

5. **Escalate confirmed injections** into the specialized skills:
   prompt-injection for direct, indirect-injection for document/web-carried,
   exfiltration-via-ai when data can leave, tool-abuse when the agent has
   callable tools. The chain anchors there take over.

6. **Record coverage:** probe families run, approximate attempt counts,
   refusals/filters observed, rate limits hit. AI-feature coverage is a
   required section of the engagement coverage report.

## Tooling

- `garak` — LLM vulnerability scanner (probe/detector framework).
- `PyRIT` (Python Risk Identification Toolkit) — scripted adversarial
  campaigns, useful for multi-turn and agentic targets.
- `references/payloads/llm-injection.md` — curated manual payloads for the
  confirmation step after automation flags a lead.

## Validation Gate (minimum proof)

- Manual reproduction of the flagged behavior through the app's real
  interface + named impact (data exfiltrated, instruction overridden, tool
  invoked). Garak detector output alone caps at lead status.
- For exfiltration claims: OOB or in-band demonstration of actual data
  leaving (oob-interactions skill applies to AI features too).

## Gotchas

- **Cost and ToS:** garak runs generate heavy traffic against provider APIs —
  confirm the engagement scope covers automated probing of the AI feature and
  any third-party model endpoint behind it (provider ToS can bind the client).
- **Non-determinism:** LLM responses vary; a one-shot success must reproduce
  (document attempts and success rate — evidence standards' race-condition
  rule applies to stochastic targets too).
- **Refusal ≠ safety:** a refusal on the obvious probe with bypass on the
  encoded variant means the filter is shallow — report the BYPASS, note the
  filter.
- **Don't leak client data into probes:** use synthetic canaries, not real
  secrets from earlier findings, as exfiltration bait — canaries make proof
  cleaner and keep evidence sanitized.
- Guard against **probe contamination**: after aggressive jailbreak runs,
  session/context state can be poisoned — reset conversations between probe
  families or results conflate.

## Chain Anchors

1. Injection confirmed → tool inventory from ai-agent-recon → tool-abuse
   (can the injected instruction invoke a tool? which one is highest-impact?).
2. Injection + RAG → indirect-injection: poison a source document and
   demonstrate persistence across users.
3. System-prompt extraction succeeded → mine it for internal endpoints,
   roles, and logic → feed recon/mapping with the disclosed internals.
