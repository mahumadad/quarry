# pentest-plugin

[![CI](https://github.com/mahumadad/pentest-plugin/actions/workflows/validate.yml/badge.svg)](https://github.com/mahumadad/pentest-plugin/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A full-cycle penetration testing plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).
Covers reconnaissance, vulnerability hunting, finding chaining, adversarial
validation, and reporting — with a deterministic evidence discipline that no
other plugin in the ecosystem provides.

> **Authorized engagements only.** This plugin is designed exclusively for
> penetration tests performed under written authorization (signed Rules of
> Engagement / Statement of Work). Never use it against systems you do not
> have explicit, documented permission to test. Unauthorized use is illegal
> and unethical.

## Features

- **124 skills** across 10 domains (recon, hunt, chain, report, SAST, AI security, platform, mapping, validation, core)
- **18 agents** with defined roles, inputs/outputs, and delegation rules
- **14 declarative workflows** (full pentest, web app, API, cloud, AD, mobile, AI agent, purple team, retest, CVE response, PR scan, surface watch, closeout, recon-only)
- **55 engine modules** — deterministic Python harness (custody, policy, OAST, chaining, nuclei runner, browser verification, budget tracking, and more)
- **40 reviewed Nuclei templates** with integrity hashes (PCI DSS 4.0, SOC 2, HIPAA, CIS v8, MITRE ATT&CK, NIST CSF, OWASP Top 10)
- **Evidence discipline**: append-only custody chain with hash-per-entry, Demonstrated/Inferred/Unproven evidence tags, anti-fabrication rules, seven-question gate for findings, and blind adversarial rebuttal

## Benchmarks

Scored against known-vulnerable applications with versioned ground truth:

| Target | Expected | Found | Recall |
|--------|----------|-------|--------|
| DVWA | 25 | 25 | 100% |
| crAPI | 10 | 10 | 100% |
| OWASP Juice Shop (v20.3.0) | 14 | 14 | 100% |

Results in [`benchmarks/results/`](benchmarks/results/).

## Installation

```bash
# Clone the repository
git clone https://github.com/mahumadad/pentest-plugin.git

# Add as a Claude Code plugin
claude plugin add /path/to/pentest-plugin
```

### Prerequisites

**Required:**
- Python 3.11+
- `pip install -r requirements.txt`

**External tools** (checked by `/pt:doctor`):
- [nmap](https://nmap.org/)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [ffuf](https://github.com/ffuf/ffuf)
- [httpx](https://github.com/projectdiscovery/httpx)

**Optional:**
- [Playwright](https://playwright.dev/) — for browser-based verification (`pip install playwright && playwright install chromium`)

Run `/pt:doctor` after installation to verify your environment.

## Quick start

```
# 1. Start an engagement (sets scope and target)
/pt:engage

# 2. Run reconnaissance
/pt:recon

# 3. Check status and coverage
/pt:status

# 4. Hunt for vulnerabilities by class
/pt:hunt

# 5. Chain findings for combined impact
/pt:chain

# 6. Validate findings adversarially
/pt:validate

# 7. Generate the report
/pt:report
```

## Architecture

```
Operator
  │
  ▼
engagement-planner ──► recon-agent ──► exploit-researcher
                                              │
                                              ▼
                       chain-analyst ◄── finding-validator
                            │                  │
                            ▼                  ▼
                       report-writer    finding-checker
                            │            (blind review)
                            ▼
                     Final deliverable
```

**Phases:** Scoping → Recon → Analysis → Exploitation Planning → Validation → Chain Analysis → Reporting → Closeout

**Human gates:** exploitation, state-modifying payloads, scope expansion, destructive actions, and pivoting all require explicit operator confirmation.

**Custody chain:** every evidence artifact is logged in an append-only, hash-chained custody log via `engine/custody.py`. Each entry is attestable after the fact.

## Project structure

```
.claude-plugin/       Plugin manifest
agents/               18 agent definitions with roles and delegation rules
commands/             18 slash commands (/pt:engage, /pt:recon, etc.)
engine/               55 Python modules — deterministic harness
hooks/                PreToolUse guard + SessionStart rules injection
skills/               126 skills organized by domain
  ├── recon/          Reconnaissance skills
  ├── hunt/           Vulnerability hunting by class
  ├── chain/          Finding chaining and graph walking
  ├── report/         Report generation and QC
  ├── sast/           Static analysis
  ├── validate/       Finding validation and evidence hygiene
  ├── core/           Core methodology skills
  ├── mapping/        Framework and compliance mapping
  ├── platform/       Platform-specific attacks (cloud, mobile, IoT)
  └── ai-security/    AI/ML-specific attack skills
workflows/            14 declarative YAML workflows
benchmarks/           Ground-truth scoring against DVWA, crAPI, Juice Shop
references/           CVSS 4.0, EPSS, ATT&CK references
lab/                  Multistack Docker lab for template validation
docs/                 Internal design docs and gap analysis
```

## Commands

| Command | Description |
|---------|-------------|
| `/pt:engage` | Start a new engagement with scope and RoE |
| `/pt:scope` | View or modify current scope |
| `/pt:recon` | Run reconnaissance phase |
| `/pt:hunt` | Hunt for vulnerabilities by class |
| `/pt:chain` | Analyze finding chains for combined impact |
| `/pt:validate` | Run adversarial validation on findings |
| `/pt:findings` | List current findings |
| `/pt:report` | Generate engagement report |
| `/pt:status` | Show engagement status and coverage |
| `/pt:doctor` | Check environment and dependencies |
| `/pt:map` | Map findings to frameworks (MITRE, NIST, OWASP) |
| `/pt:export` | Export findings in various formats |
| `/pt:deliver` | Package and deliver final report |
| `/pt:closeout` | Close engagement with coverage summary |
| `/pt:resume` | Resume a paused engagement |
| `/pt:retest` | Re-test previously found vulnerabilities |
| `/pt:run` | Execute a named workflow |
| `/pt:notify` | Send engagement notifications |

## How it differs from other tools

This plugin does not compete on tool count or autonomy. Its differentiator
is **evidence integrity**:

- **Custody chain** — append-only, hash-chained log of every evidence artifact
- **Three-level evidence tags** — Demonstrated, Inferred, Unproven
- **Anti-fabrication rules** — no finding without reproducible evidence
- **Blind adversarial rebuttal** — `finding-checker` reviews in isolation, without engagement context
- **Detection pairing** — every offensive technique is paired with its detection opportunity
- **Fail-closed scope guard** — `engine/guard.py` blocks out-of-scope commands by default

## Contributing

Contributions are welcome. Please ensure any changes maintain the evidence
discipline and scope-guard invariants. Run the validation suite before
submitting:

```bash
python3 -m pytest tests/
```

## License

[MIT](LICENSE) — see the license file for details.

**Reminder:** This tool is for authorized security testing only. The MIT
license grants permission to use the software, not permission to test
systems you don't own or have written authorization to test.
