#!/usr/bin/env python3
"""Validate pentest plugin structure and completeness."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ERRORS = []
WARNINGS = []


def error(msg):
    ERRORS.append(msg)
    print(f"  ERROR: {msg}")


def warn(msg):
    WARNINGS.append(msg)
    print(f"  WARN:  {msg}")


def ok(msg):
    print(f"  OK:    {msg}")


def check_plugin_json():
    print("\n=== plugin.json ===")
    p = ROOT / ".claude-plugin" / "plugin.json"
    if not p.exists():
        error("Missing .claude-plugin/plugin.json")
        return
    data = json.loads(p.read_text())
    for key in ("name", "version", "private"):
        if key not in data:
            error(f"plugin.json missing key: {key}")
        else:
            ok(f"plugin.json has {key}={data[key]}")
    if not data.get("private"):
        warn("plugin.json should be private:true")


def check_claude_md():
    print("\n=== CLAUDE.md ===")
    p = ROOT / "CLAUDE.md"
    if not p.exists():
        error("Missing CLAUDE.md")
        return
    text = p.read_text()
    required_sections = [
        "Scope", "Anti-fabricación", "CLI anti-alucinación",
        "Memory-first", "Gates humanos", "Evidencia", "Cobertura", "Budget"
    ]
    for section in required_sections:
        if section.lower() in text.lower():
            ok(f"CLAUDE.md has section: {section}")
        else:
            warn(f"CLAUDE.md missing section: {section}")


def check_hooks():
    print("\n=== Hooks ===")
    p = ROOT / "hooks" / "hooks.json"
    if not p.exists():
        error("Missing hooks/hooks.json")
        return
    data = json.loads(p.read_text())
    hook_types = [h.get("event") for h in data] if isinstance(data, list) else list(data.keys())
    ok(f"hooks.json has events: {hook_types}")


def check_engine():
    print("\n=== Engine ===")
    expected = [
        "__init__.py", "state.py", "scope.py", "findings.py",
        "chain_engine.py", "rebuttal.py", "budget.py",
        "loop_detector.py", "coverage.py", "guard.py"
    ]
    engine_dir = ROOT / "engine"
    for f in expected:
        p = engine_dir / f
        if p.exists():
            size = p.stat().st_size
            if size < 100:
                warn(f"engine/{f} exists but is very small ({size} bytes)")
            else:
                ok(f"engine/{f} ({size} bytes)")
        else:
            error(f"Missing engine/{f}")


def check_engine_imports():
    print("\n=== Engine imports ===")
    try:
        sys.path.insert(0, str(ROOT))
        from engine.state import EngagementState, Phase
        ok("engine.state imports OK")
        from engine.scope import Scope
        ok("engine.scope imports OK")
        from engine.findings import FindingsStore, Finding, FindingStatus, EvidenceTag
        ok("engine.findings imports OK")
        from engine.chain_engine import ChainEngine, KNOWN_CHAINS, ENABLES_MAP
        ok(f"engine.chain_engine imports OK ({len(KNOWN_CHAINS)} known chains)")
        from engine.rebuttal import RebuttalEngine, REFUTATION_QUESTIONS
        ok(f"engine.rebuttal imports OK ({len(REFUTATION_QUESTIONS)} refutation questions)")
        from engine.budget import BudgetManager
        ok("engine.budget imports OK")
        from engine.loop_detector import LoopDetector
        ok("engine.loop_detector imports OK")
        from engine.coverage import CoverageTracker, ALL_VULN_CLASSES
        ok(f"engine.coverage imports OK ({len(ALL_VULN_CLASSES)} vuln classes)")
    except Exception as e:
        error(f"Engine import failed: {e}")


def check_agents():
    print("\n=== Agents ===")
    expected = [
        "engagement-planner.md", "recon-agent.md", "exploit-researcher.md",
        "chain-analyst.md", "finding-validator.md", "finding-checker.md",
        "report-writer.md", "network-analyst.md"
    ]
    agents_dir = ROOT / "agents"
    for f in expected:
        p = agents_dir / f
        if p.exists():
            ok(f"agents/{f}")
        else:
            error(f"Missing agents/{f}")


def check_commands():
    print("\n=== Commands ===")
    expected = [
        "engage.md", "recon.md", "map.md", "hunt.md", "chain.md",
        "validate.md", "report.md", "scope.md", "status.md", "findings.md"
    ]
    cmd_dir = ROOT / "commands"
    for f in expected:
        p = cmd_dir / f
        if p.exists():
            ok(f"commands/{f}")
        else:
            error(f"Missing commands/{f}")


def check_workflows():
    print("\n=== Workflows ===")
    expected = [
        "full-pentest.yaml", "web-app-pentest.yaml", "api-pentest.yaml",
        "cloud-pentest.yaml", "ad-pentest.yaml", "mobile-pentest.yaml",
        "ai-agent-pentest.yaml", "recon-only.yaml"
    ]
    wf_dir = ROOT / "workflows"
    for f in expected:
        p = wf_dir / f
        if p.exists():
            ok(f"workflows/{f}")
        else:
            error(f"Missing workflows/{f}")


def check_presets():
    print("\n=== Presets ===")
    expected = ["full-audit.yaml", "bug-bounty.yaml", "quick-recon.yaml"]
    pre_dir = ROOT / "presets"
    for f in expected:
        p = pre_dir / f
        if p.exists():
            ok(f"presets/{f}")
        else:
            error(f"Missing presets/{f}")


def check_templates():
    print("\n=== Templates ===")
    expected = [
        "finding-template.md", "target-card.md", "chain-report.md",
        "engagement-report.md", "executive-summary.md"
    ]
    tpl_dir = ROOT / "templates"
    for f in expected:
        p = tpl_dir / f
        if p.exists():
            ok(f"templates/{f}")
        else:
            error(f"Missing templates/{f}")


def check_skills():
    print("\n=== Skills ===")
    expected_categories = {
        "core": ["engagement-flow", "scope-discipline", "finding-discipline", "opsec-discipline"],
        "recon": [
            "passive-recon", "active-recon", "dns-enumeration", "subdomain-discovery",
            "port-scan", "service-enumeration", "web-crawling", "js-analysis",
            "api-discovery", "osint", "cloud-recon", "email-harvesting",
            "github-dorking", "waf-fingerprint", "tech-stack-fingerprint"
        ],
        "mapping": ["asset-map", "trust-map", "identity-map", "state-map", "capability-map"],
        "hunt": [
            "sqli", "xss", "ssrf", "idor", "csrf", "rce", "ssti", "xxe",
            "lfi-rfi", "auth-bypass", "race-condition", "cors", "open-redirect",
            "info-disclosure", "deserialization", "graphql", "websocket", "jwt",
            "hunt-oauth", "hunt-api-abuse", "hunt-file-upload", "hunt-cache-poisoning",
            "hunt-http-smuggling", "hunt-subdomain-takeover", "hunt-crlf-injection",
            "hunt-clickjacking", "hunt-host-header", "hunt-parameter-pollution",
            "hunt-prototype-pollution", "hunt-mass-assignment", "hunt-broken-access-control",
            "hunt-business-logic", "hunt-rate-limiting", "hunt-password-reset",
            "hunt-2fa-bypass", "hunt-session-management", "hunt-email-injection"
        ],
        "chain": [
            "chain-analysis", "chain-web-to-rce", "chain-auth-to-takeover",
            "chain-info-to-exploit", "chain-ssrf-to-cloud", "chain-custom",
            "chain-graph-walk", "chain-multi-app"
        ],
        "validate": ["finding-validation", "triage-gate", "evidence-hygiene", "dedup"],
        "report": ["report-writing", "framework-mapping", "executive-brief"],
        "platform": [
            "aws-attack", "azure-attack", "gcp-attack", "active-directory",
            "kubernetes-attack", "docker-attack", "mobile-android", "mobile-ios",
            "iot-ics", "wordpress-attack", "windows-privesc", "linux-privesc",
            "network-infra"
        ],
        "ai-security": [
            "ai-agent-recon", "prompt-injection", "indirect-injection",
            "rag-poisoning", "tool-abuse", "exfiltration-via-ai", "ai-supply-chain"
        ],
    }

    total_expected = 0
    total_found = 0
    for category, skills in expected_categories.items():
        found = 0
        for skill in skills:
            p = ROOT / "skills" / category / skill / "SKILL.md"
            if p.exists():
                found += 1
                total_found += 1
            else:
                warn(f"Missing skills/{category}/{skill}/SKILL.md")
        total_expected += len(skills)
        status = "OK" if found == len(skills) else f"{found}/{len(skills)}"
        print(f"  {'OK' if found == len(skills) else 'PARTIAL'}: {category}: {status}")

    print(f"\n  TOTAL SKILLS: {total_found}/{total_expected}")


def check_references():
    print("\n=== References ===")
    expected_root = [
        "cli-rules.md", "anti-fabrication-rules.md", "finding-evidence-standards.md"
    ]
    expected_chains = ["chain-matrix.md", "chain-patterns.md", "pivot-graph.md"]
    expected_frameworks = [
        "mitre-attack-mapping.md", "nist-csf-mapping.md", "owasp-top10-mapping.md"
    ]

    ref_dir = ROOT / "references"
    for f in expected_root:
        p = ref_dir / f
        if p.exists():
            ok(f"references/{f}")
        else:
            warn(f"Missing references/{f}")

    for f in expected_chains:
        p = ref_dir / "chains" / f
        if p.exists():
            ok(f"references/chains/{f}")
        else:
            warn(f"Missing references/chains/{f}")

    for f in expected_frameworks:
        p = ref_dir / "frameworks" / f
        if p.exists():
            ok(f"references/frameworks/{f}")
        else:
            warn(f"Missing references/frameworks/{f}")

    gotcha_dir = ref_dir / "gotchas"
    if gotcha_dir.exists():
        gotchas = list(gotcha_dir.glob("*.md"))
        ok(f"references/gotchas/: {len(gotchas)} files")
    else:
        warn("Missing references/gotchas/ directory")


def main():
    print("=" * 60)
    print("PENTEST PLUGIN VALIDATION")
    print("=" * 60)

    check_plugin_json()
    check_claude_md()
    check_hooks()
    check_engine()
    check_engine_imports()
    check_agents()
    check_commands()
    check_workflows()
    check_presets()
    check_templates()
    check_skills()
    check_references()

    print("\n" + "=" * 60)
    print(f"RESULTS: {len(ERRORS)} errors, {len(WARNINGS)} warnings")
    print("=" * 60)

    if ERRORS:
        print("\nERRORS (must fix):")
        for e in ERRORS:
            print(f"  - {e}")

    if WARNINGS:
        print("\nWARNINGS (should fix):")
        for w in WARNINGS:
            print(f"  - {w}")

    return 1 if ERRORS else 0


if __name__ == "__main__":
    sys.exit(main())
