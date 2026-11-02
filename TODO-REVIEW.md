# pentest-plugin — Review Fix List

Consolidated from the independent technical review (Nov 2026 PDF) and
operator analysis. Items are ordered by priority: P0 blocks correct
operation, P1 blocks quality claims, P2 builds adoption.

All text in English (repo is public).

---

## P0 — Critical (plugin is broken without these)

### C-1: Rewrite hooks.json to the official schema
**Current:** flat array of objects with `event`, `matcher`, `tool_name`,
`commands` — a format Claude Code ignores silently.
**Required:** keyed by event name (`SessionStart`, `PreToolUse`), each
containing an array of config objects with `matcher` and `hooks` (array
of `{type: "command", command: "..."}`).\
Also: `$TOOL_INPUT` does not exist; guard.py must read JSON from stdin.\
**Verify:** open a session — CLAUDE.md text appears; a Bash call outside
scope is blocked by guard.py.

### C-2: Fix plugin.json (schema compliance)
- Remove `private: true` (not in Claude Code plugin schema; contradicts
  public repo).
- Change `author` from string to object: `{"name": "mahumadad"}`.
- Add `license: "MIT"` (must match LICENSE file).
- Add `repository`, `homepage`, `keywords`, `documentationUrl`.
- Consider: `mcpServers`, marketplace entry fields.
**Verify:** `validate_plugin` passes with no warnings.

### C-3: Add `description` to 8 agents
Without `description`, the runtime cannot delegate to them. Agents:
- `agents/chain-analyst.md`
- `agents/engagement-planner.md`
- `agents/exploit-researcher.md`
- `agents/finding-checker.md`
- `agents/finding-validator.md`
- `agents/network-analyst.md`
- `agents/recon-agent.md`
- `agents/report-writer.md`

Keep existing custom fields (layer, phases, mitre_tactics, etc.) — just
add `description:` to frontmatter.\
**Verify:** all 18 agents listed by runtime after plugin reload.

### C-4: Add YAML frontmatter to 5 invisible skills
Skills without `---` / `name:` / `description:` are invisible to the
skill loader:
- `skills/hunt/credential-testing/SKILL.md`
- `skills/hunt/post-exploitation/SKILL.md`
- `skills/hunt/lateral-movement/SKILL.md`
- `skills/hunt/persistence-check/SKILL.md`
- `skills/hunt/data-exfiltration-test/SKILL.md`

**Verify:** 126/126 skills listed after reload.

### C-5: Add LICENSE file (MIT)
No LICENSE file exists. `UNLICENSED` in plugin.json means nobody can
legally use, fork, or contribute.\
**Action:** create `LICENSE` with MIT text, update plugin.json.

### C-6: Write README.md
The repo is public with zero docs. Must include:
- Legal disclaimer (authorized engagements only)
- Installation (clone + claude plugin path)
- Prerequisites + `/pt:doctor`
- Quick start: `/pt:engage` → `/pt:recon` → `/pt:status`
- Architecture overview (phases, engine, custody chain)
- CI badge
- Benchmark results (DVWA 25/25, crAPI 10/10, Juice Shop 14/14)
- Example session snippet
- Links to internal docs

**Verify:** GitHub shows README, license badge, CI badge.

---

## P1 — Important (quality / consistency)

### I-1: Eliminate duplicate skills
Two pairs doing the same thing:
- `skills/recon/subdomain-enum/` ↔ `skills/recon/subdomain-discovery/`
  → keep `subdomain-discovery`, delete `subdomain-enum`
- `skills/recon/tech-fingerprint/` ↔ `skills/recon/tech-stack-fingerprint/`
  → keep `tech-stack-fingerprint`, delete `tech-fingerprint`

Also in engine:
- `engine/poc_gen.py` ↔ `engine/poc_generator.py`
  → keep `poc_gen.py` (referenced by gap analysis), delete `poc_generator.py`

Update all references in workflows, agents, and docs.\
**Verify:** `grep` finds no references to deleted names.

### I-2: Unify skill naming convention
39 skills use category prefix (`hunt-xss`, `recon-subdomain-enum`), 87
don't (`sqli`, `cors`, `graphql`). The directory already categorizes.
- Convention: **no prefix** (directory is the category).
- Remove `recon-` and `hunt-` prefixes from `name:` in SKILL.md.
- Update all workflow YAML references, engine, agents, docs.
- Update validator to enforce no-prefix convention.

**Verify:** validator rejects prefixed names; all workflows resolve.

### I-3: Complete requirements.txt
Missing runtime deps found in engine imports:
- `requests` — used in http_client.py
- `urllib3` — used directly

Optional deps (lazy-imported, with graceful fallback):
- `playwright` — browser_loop.py, browser_verify.py

Split into:
- `requirements.txt` — core deps
- `requirements-optional.txt` — playwright, etc.

**Verify:** clean venv install + `python3 -c "import engine"` succeeds.

### I-4: Verify command namespace (`/pt:*` vs `/pentest:*`)
Commands in `commands/` declare as `pt:hunt`, `pt:engage`, etc. But the
plugin name is `pentest`, so runtime may resolve as `/pentest:hunt`.\
**Action:** test in a live session. If `/pt:*` doesn't work, either:
- Rename plugin to `pt` in plugin.json, or
- Update all 18 command files + docs to use `pentest:` prefix.

**Verify:** documented command invokes the actual command.

### ~~I-5: Add happy-path tests for gap-analysis modules~~ DONE
26 happy-path tests added in `tests/test_engine_modules.py` covering:
redaction, tracing, checkpoint, leads, priority, guard, decision_engine,
brain, detection_rules, episodic, fix_suggest, target_diff, poc_gen,
validation, workflows. Total suite: 56 tests, 0 failures.
4 modules skipped (external-tool wrappers: browser_loop, browser_verify,
headless, mcp_client).

### ~~I-6: Harden the validator~~ DONE
`tests/validate_plugin.py` now validates:
- hooks.json against official Claude Code schema (keyed events, hooks arrays)
- YAML frontmatter presence + name/description in all skills, agents, commands
- Workflow YAML skill references resolve to existing skill directories
- plugin.json schema (no private, author as object, license)
- LICENSE and README presence and content
Result: 0 errors, 22 warnings (all cosmetic).

### ~~I-7: Add marketplace.json~~ DONE
Created `.claude-plugin/marketplace.json` with install config, requirements,
external tools, command list, and category metadata.

---

## P2 — Adoption / polish

### A-1: Declare mcpServers in plugin.json
Expose Nuclei runner, tool registry, and browser verifier as MCP
servers so other agents can consume them.

### A-2: Publish headless CI action
`action.yml` for PR-scan with SARIF export to GitHub Code Scanning.

### A-3: Automate weekly benchmark in CI
Juice Shop benchmark in GitHub Actions, results committed as JSON +
badge.

### A-4: Write DVWA 23/23 writeup
Public post with the benchmark story — evidence discipline angle.

### A-5: Refresh gap analysis
CAI archived (Oct 2026), claude-pentest added, Claude Code Security
layer added. Update `docs/GAP-ANALYSIS.md` with Nov 2026 sources.

### A-6: Clean up untracked files
- `ct-kriptome.json` — client data, should not be in repo root
- `references/nuclei-manifest.json.bak` — backup file

---

## Execution order

The review recommends this sequence:

1. **C-1** hooks.json → everything else depends on rules loading
2. **C-2** plugin.json + **C-5** LICENSE → schema compliance
3. **C-3** agents + **C-4** skills → full runtime visibility
4. **C-6** README → public face
5. **I-1** duplicates + **I-2** naming → consistency
6. **I-3** requirements → reproducibility
7. **I-4** namespace → verify
8. **I-5** tests + **I-6** validator → regression safety
9. **I-7** marketplace → distribution
10. **P2** items → adoption

Each step is a self-contained commit.
