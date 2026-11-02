# Quarry

**Track. Aim. Prove.**

[![CI](https://github.com/mahumadad/quarry/actions/workflows/validate.yml/badge.svg)](https://github.com/mahumadad/quarry/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Quarry is a full-cycle penetration testing plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). It turns an AI coding agent into a methodical security tester — from recon through reporting — with a deterministic evidence chain that no other plugin in the ecosystem provides.

Every finding is tracked, every claim is proven, every artifact is custody-logged. No hallucinated vulns. No unverified severity. No guesswork in your report.

> **Authorized engagements only.** Quarry is designed exclusively for penetration tests performed under written authorization (signed RoE / SoW). Never use it against systems you do not have explicit permission to test.

---

## Why Quarry?

Most AI pentest tools optimize for **autonomy** — more tools, more actions, less human oversight. Quarry optimizes for **proof**:

| What others do | What Quarry does |
|---|---|
| Report findings based on version banners | Require PoC or evidence before any finding |
| Trust the AI's classification | Blind adversarial rebuttal by an independent agent |
| Flat list of vulnerabilities | Attack chains with BFS graph walking |
| "We found 47 vulnerabilities" | Custody-grade evidence log, hash-chained, attestable |

**The result:** reports that survive scrutiny. Findings that reproduce. Evidence that holds up.

---

## What's inside

- **124 skills** across 10 domains (recon, hunt, chain, report, SAST, AI security, platform, mapping, validation, core)
- **18 specialized agents** — each with defined roles, inputs/outputs, and delegation rules
- **14 declarative workflows** — full pentest, web app, API, cloud, AD, mobile, AI agent, purple team, retest, CVE response, PR scan, surface watch, closeout, recon-only
- **55 engine modules** — deterministic Python harness: custody, policy, OAST, chaining, nuclei runner, browser verification, budget tracking
- **40 reviewed Nuclei templates** — integrity-hashed, mapped to PCI DSS 4.0, SOC 2, HIPAA, CIS v8, MITRE ATT&CK, NIST CSF, OWASP Top 10
- **Evidence discipline** — append-only custody chain, Demonstrated/Inferred/Unproven evidence tags, anti-fabrication rules, seven-question gate, blind adversarial rebuttal

---

## Benchmarks

Scored against known-vulnerable applications with versioned ground truth:

| Target | Type | Expected | Found | Recall | Evidence integrity |
|--------|------|----------|-------|--------|--------------------|
| DVWA | Web (PHP) | 25 | 25 | **100%** | 100% |
| crAPI | REST API | 10 | 10 | **100%** | 100% |
| Juice Shop v20.3.0 | Web (Node) | 14 | 14 | **100%** | 100% |
| DVGA | GraphQL | 20 | — | pending | — |
| VAmPI | REST API (OWASP API Top 10) | 9 | — | pending | — |
| WebGoat | Web (Java) | 21 | — | pending | — |

Full results: [`benchmarks/results/`](benchmarks/results/). Target definitions: [`benchmarks/targets/`](benchmarks/targets/). Weekly CI runs on Mondays.

---

## Quick start

```bash
git clone https://github.com/mahumadad/quarry.git
claude plugin add /path/to/quarry
```

```
/quarry:doctor            # Check your environment
/quarry:engage            # Set scope and target
/quarry:recon             # Reconnaissance
/quarry:hunt              # Hunt by vulnerability class
/quarry:chain             # Chain findings for combined impact
/quarry:validate          # Adversarial validation
/quarry:report            # Generate the report
```

### Prerequisites

**Required:** Python 3.11+ and `pip install -r requirements.txt`

**External tools** (checked by `/quarry:doctor`):
[nmap](https://nmap.org/) ·
[nuclei](https://github.com/projectdiscovery/nuclei) ·
[ffuf](https://github.com/ffuf/ffuf) ·
[httpx](https://github.com/projectdiscovery/httpx)

**Optional:** [Playwright](https://playwright.dev/) for browser-based XSS/clickjacking verification

---

## How it works

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

**Custody chain:** every evidence artifact is logged in an append-only, hash-chained custody log. Each entry is attestable after the fact.

---

## Commands

| Command | What it does |
|---------|-------------|
| `/quarry:engage` | Start engagement with scope and RoE |
| `/quarry:scope` | View or modify scope |
| `/quarry:recon` | Run reconnaissance |
| `/quarry:hunt` | Hunt vulnerabilities by class |
| `/quarry:chain` | Analyze finding chains |
| `/quarry:validate` | Adversarial validation pipeline |
| `/quarry:findings` | List current findings |
| `/quarry:report` | Generate report |
| `/quarry:status` | Engagement status and coverage |
| `/quarry:doctor` | Check environment |
| `/quarry:map` | Map to MITRE, NIST, OWASP |
| `/quarry:export` | Export as SARIF, JSON, CSV |
| `/quarry:deliver` | Package and deliver |
| `/quarry:closeout` | Close with coverage summary |
| `/quarry:resume` | Resume paused engagement |
| `/quarry:retest` | Re-test remediated vulns |
| `/quarry:run` | Execute a workflow |
| `/quarry:notify` | Escalate critical finding |

---

## Project structure

```
.claude-plugin/       Plugin manifest and marketplace config
agents/               18 agent definitions with roles and delegation
commands/             18 slash commands (/quarry:*)
engine/               55 Python modules — deterministic harness
hooks/                PreToolUse guard + SessionStart rules
skills/               124 skills across 10 domains
workflows/            14 declarative YAML workflows
benchmarks/           Ground-truth scoring (DVWA, crAPI, Juice Shop)
references/           CVSS 4.0, EPSS, ATT&CK references
lab/                  Multistack Docker lab for template validation
docs/                 Design docs and gap analysis
```

---

## CI & reusable action

Quarry ships a [GitHub Action](action.yml) for PR-level security scanning with SARIF export:

```yaml
- uses: mahumadad/quarry@main
  with:
    sarif: "true"
```

Results upload to GitHub Code Scanning automatically.

---

## Contributing

Contributions welcome. Maintain the evidence discipline and scope-guard invariants. Run validation before submitting:

```bash
python3 -m pytest tests/
```

## License

[MIT](LICENSE) — the license grants permission to use the software, not permission to test systems you don't own or have written authorization to test.
