---
name: supply-chain-audit
description: >
  Audit third-party dependencies (npm, PyPI, Go modules, Maven, Rubygems, crates) for
  version-matched known vulnerabilities, abandoned upstreams, install-script malware,
  publisher/typosquat risk, and license exposure. Use in any engagement with source or
  manifest access: package.json, requirements.txt, go.mod, pom.xml, Gemfile, Cargo.toml,
  lockfiles. Keywords: SCA, dependency audit, supply chain, osv-scanner, grype, npm audit,
  pip-audit, govulncheck, typosquat, install scripts, lockfile, SBOM, EPSS, KEV.
  Do NOT use for first-party code review (use code-review / static-analysis-toolkit).
metadata:
  type: sast
  phase: hunting
  cwe: [CWE-1395, CWE-1104]
  mitre_attack: [T1195.001, T1195.002]
  tools: [osv-scanner, grype, npm-audit, pip-audit, govulncheck, syft]
depends_on: [code-review, scope-discipline]
feeds_into: [finding-validation, report-writing]
chains_with: [rce, info-disclosure]
---

## Purpose

First-party SAST covers code the client wrote. Most real exposure ships in
code they imported. This skill produces version-matched, reachability-noted
dependency findings — NOT raw scanner dumps. A dependency finding without a
demonstrated or credible reachability path follows the same anti-fabrication
rules as everything else.

## Methodology

1. **Enumerate manifests AND lockfiles.** Lockfiles are ground truth —
   `package.json` says `^4.17.0`, `package-lock.json` says what is actually
   deployed. Missing lockfile in a repo that should have one is itself a
   process finding (info).

2. **Scan with an advisory DB, version-matched:**
   ```bash
   osv-scanner -r .                    # multi-ecosystem, OSV database
   grype dir:.                         # SBOM-driven, grype + syft
   pip-audit -r requirements.txt       # Python
   govulncheck ./...                   # Go — includes reachability analysis
   npm audit --package-lock-only       # npm without touching node_modules
   ```

3. **Enrich with exploitation intelligence** (references/cvss4-epss-kev.md):
   for each CVE/GHSA hit, pull EPSS score and CISA KEV membership. A
   critical-CVSS dependency bug with EPSS 0.1% ranks below a medium with
   KEV listing. Record both in the finding metadata.

4. **Reachability triage — the step that separates audit from scanner dump.**
   For each vulnerable dependency: is the vulnerable FUNCTION actually called
   by first-party code? (`govulncheck` does this for Go automatically; for
   others, grep imports + call sites via the static-analysis-toolkit.) Tag
   each finding: `reachable` (treat like a real vuln — try to demonstrate via
   the relevant hunt skill), `present-not-reachable` (report as hardening,
   lower severity), `unknown` (state it).

5. **Abandonment and publisher risk:**
   - Last release / last commit age; maintainer count; open security issues.
   - Install scripts (`preinstall`/`postinstall` in npm, `setup.py` exec in
     legacy Python) — enumerate and read them; they run with build privileges.
   - Typosquat/dependency-confusion check: internal-looking package names
     resolved from PUBLIC registries = dependency confusion finding (high).
   - Transitive depth: a vuln 6 levels deep in a dev-only tree ≠ same risk as
     a direct production dependency. Record the dependency path.

6. **Demonstrate where possible.** A reachable, exploitable dependency vuln
   in a RUNNING target (e.g., known CVE in an exposed endpoint's library)
   should be triggered against the live app per the CVE's PoC — that promotes
   it from "dependency audit note" to a Demonstrated finding. Version-only
   matching without trigger caps at Inferred (anti-fabrication rules).

## Validation Gate (minimum proof)

- Scanner output alone is a lead. Minimum for a reported finding: affected
  version confirmed in the LOCKFILE + advisory ID + reachability tag
  (reachable / not-reachable / unknown) + EPSS/KEV enrichment.
- `Demonstrated` requires the live trigger (exploit fired against the running
  target within scope) — same bar as any other class.

## Gotchas

- **npm audit false confidence:** `npm audit fix` suggestions can be breaking;
  never run fix commands against a client repo without a gate.
- **Transitive ≠ unimportant, but rank it:** report direct-production first,
  transitive with EPSS/KEV second, dev-only last.
- **Private registries:** internal mirrors may serve stale metadata — verify
  the resolved version from the lockfile/artifact, not the registry listing.
- **License findings** (GPL in proprietary SaaS) belong in the report's
  process/observations section, not as security vulnerabilities.
- Batch-dumping 200 transitive advisories into a report is scanner theater —
  dedupe, group by package, and gate by severity mode (findings.py
  HUNT_MODE_SEVERITY_GATES).

## Chain Anchors

1. Reachable RCE-class dependency vuln → attempt live trigger → chains to rce.
2. Dependency confusion (internal name on public registry) → can YOU register
   it? (Do NOT register without an operator gate — but document the exposure.)
3. Vulnerable auth/crypto library → feed the affected function list to the
   relevant hunt skill (jwt, session-management) for live testing.
