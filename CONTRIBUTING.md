# Contributing to Quarry

## Before You Start

- All text in the repository must be in **English** (the repo is public).
- Security vulnerabilities go through [SECURITY.md](SECURITY.md), not GitHub Issues.

## Submitting Changes

1. **One change per PR.** Don't bundle unrelated fixes. Separate refactors from
   behavior changes.
2. **Follow existing code style.** Match the patterns in the file you're editing.
3. **Run the validator** before submitting:
   ```bash
   python tests/validate_plugin.py
   ```
4. **Run the test suite** if you changed engine code:
   ```bash
   python -m pytest tests/
   ```
5. **Write a clear commit message:** imperative first line, body explains the
   *why* (the diff shows the *what*).

## Structure

- `commands/` — Slash command definitions (frontmatter + instructions)
- `skills/` — Technique-specific skill files
- `agents/` — Agent role definitions
- `workflows/` — Multi-phase workflow orchestrations
- `engine/` — Python runtime (policy, artifacts, findings, custody, etc.)
- `references/` — Standing reference documents (anti-fabrication, CVSS, etc.)
- `templates/` — Finding and report templates

## Adding a Skill

1. Create `skills/<phase>/<skill-name>/SKILL.md` with the standard frontmatter
   (`name`, `description`, `metadata`, `depends_on`, `feeds_into`).
2. Ensure `depends_on` references point to existing skills (the validator checks this).
3. If the skill introduces a new vuln class, add it to `engine/coverage.py`.

## Adding an Agent

1. Create `agents/<agent-name>.md` with frontmatter (`name`, `description`,
   `model`, `tools`, `layer`, `phases`).
2. Wire it to at least one workflow phase, or document it as auxiliary.
