# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Policy engine hardening (C3):** command_policy() now tokenizes full commands, unwraps
  shell wrappers (bash -c, env, sudo), and covers ssh/openssl/socat/telnet
- **Artifact immutability (C4):** artifact IDs use UUID instead of content-derived hashes;
  paths include timestamps; existing artifacts are never overwritten
- **Finding evidence gate (C5):** new findings must start as `detected`; transition to
  `validated` requires evidence and a non-unproven tag; exporters double-check evidence
- **CI action reliability (C6):** removed `|| true` from validator/test steps; fixed output
  parsers to match actual format; removed bare except in SARIF generation
- **Network scope enforcement (I1):** browser navigation, browser-verify probes, and MCP
  tool calls now validate URLs against PolicyEngine scope
- **Broken skill/workflow references (I2):** fixed 38+ stale references across 31 files;
  created 4 missing closeout skills; added skills→skills validator
- **CVSS 4.0 as primary (I7):** finding-validator, seven-question-gate, finding-discipline,
  and finding-template updated; CVSS 3.1 kept as optional
- **Custody chain description (I9):** updated from "attestable" to "locally tamper-evident"
- **Benchmark claims (I10):** README clarifies results are from manual runs, not automated CI

### Changed
- **Language unification (I3):** all commands, workflows, and phase descriptions translated
  from Spanish to English for public repo consistency
- **Vuln class counts (I6):** removed hardcoded counts from commands to prevent drift
- **Agent wiring (I4):** 11 previously unwired agents now assigned to workflows
  (engagement-planner, network-analyst, browser-verifier, ai-agent-exploit, 6 SAST agents)
- **Finding-checker blindness (I5):** documented as prompt-level directive (no runtime
  enforcement yet)
- **plugin.json (I8):** added mcpServers.browser-verifier declaring Claude Browser tool
  dependencies
- Removed absolute claims from README intro
- Archived outdated TODO-REVIEW.md

### Added
- `url_policy()` function for shared URL scope validation
- `check_skill_deps()` validator for skills→skills reference integrity
- 4 closeout skills: artifact-cleanup, credential-hygiene, evidence-seal, data-retention
- SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, pyproject.toml

## [0.1.0] - 2026-10-15

Initial release with full pentest lifecycle: recon, mapping, hunting, chaining,
validation, reporting, and closeout. 18 commands, 14 workflows, 18 agents,
46+ hunt skills, and engine modules for policy, artifacts, findings, custody,
coverage, chains, OAST, and browser verification.
