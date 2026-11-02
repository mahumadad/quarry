#!/usr/bin/env python3
"""Validate pentest plugin structure, content correctness and completeness."""

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

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


def _parse_frontmatter(path: Path) -> dict | None:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
    if not match:
        return None
    raw = match.group(1)
    if yaml:
        safe_raw = re.sub(r"\[\*\]", '["*"]', raw)
        safe_raw = re.sub(r"- \*\s*$", '- "*"', safe_raw, flags=re.MULTILINE)
        try:
            return yaml.safe_load(safe_raw) or {}
        except yaml.YAMLError:
            pass
    result = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith(" "):
            key, _, val = line.partition(":")
            result[key.strip()] = val.strip()
    return result


def check_plugin_json():
    print("\n=== plugin.json ===")
    p = ROOT / ".claude-plugin" / "plugin.json"
    if not p.exists():
        error("Missing .claude-plugin/plugin.json")
        return
    data = json.loads(p.read_text())
    for key in ("name", "version", "description"):
        if key not in data:
            error(f"plugin.json missing required key: {key}")
        else:
            ok(f"plugin.json has {key}={data[key]!r:.60}")
    if "private" in data:
        error("plugin.json contains 'private' (not in Claude Code schema)")
    author = data.get("author")
    if isinstance(author, str):
        error("plugin.json 'author' must be an object {name:...}, not a string")
    elif isinstance(author, dict) and "name" in author:
        ok(f"plugin.json author={author}")
    else:
        warn("plugin.json missing author.name")
    if "license" not in data:
        warn("plugin.json missing 'license'")
    elif data["license"] != "MIT":
        warn(f"plugin.json license is {data['license']!r}, expected 'MIT'")
    else:
        ok("plugin.json license=MIT")
    for opt in ("repository", "homepage", "keywords", "documentationUrl"):
        if opt in data:
            ok(f"plugin.json has {opt}")
        else:
            warn(f"plugin.json missing optional field: {opt}")


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
    if not isinstance(data, dict) or "hooks" not in data:
        error("hooks.json must have top-level 'hooks' object (official schema)")
        return
    hooks_obj = data["hooks"]
    if not isinstance(hooks_obj, dict):
        error("hooks.json 'hooks' must be an object keyed by event name")
        return
    valid_events = {"SessionStart", "PreToolUse", "PostToolUse", "Notification",
                    "Stop", "SubagentTool"}
    for event, configs in hooks_obj.items():
        if event not in valid_events:
            warn(f"hooks.json: unknown event '{event}'")
        if not isinstance(configs, list):
            error(f"hooks.json: event '{event}' value must be an array")
            continue
        for i, config in enumerate(configs):
            if not isinstance(config, dict):
                error(f"hooks.json: {event}[{i}] must be an object")
                continue
            if "hooks" not in config:
                error(f"hooks.json: {event}[{i}] missing 'hooks' array")
            elif not isinstance(config["hooks"], list):
                error(f"hooks.json: {event}[{i}].hooks must be an array")
            else:
                for j, hook in enumerate(config["hooks"]):
                    if not isinstance(hook, dict) or "type" not in hook:
                        error(f"hooks.json: {event}[{i}].hooks[{j}] missing 'type'")
                    elif hook["type"] == "command" and "command" not in hook:
                        error(f"hooks.json: {event}[{i}].hooks[{j}] type=command but missing 'command'")
    ok(f"hooks.json schema validated (events: {list(hooks_obj.keys())})")


def check_agents():
    print("\n=== Agents ===")
    agents_dir = ROOT / "agents"
    if not agents_dir.exists():
        error("Missing agents/ directory")
        return
    for agent_file in sorted(agents_dir.glob("*.md")):
        fm = _parse_frontmatter(agent_file)
        if fm is None:
            error(f"agents/{agent_file.name}: missing YAML frontmatter")
            continue
        if "name" not in fm:
            error(f"agents/{agent_file.name}: frontmatter missing 'name'")
        if "description" not in fm:
            error(f"agents/{agent_file.name}: frontmatter missing 'description' (runtime cannot delegate)")
        else:
            ok(f"agents/{agent_file.name}: name={fm.get('name')}, has description")


def check_commands():
    print("\n=== Commands ===")
    expected = [
        "engage.md", "recon.md", "map.md", "hunt.md", "chain.md",
        "validate.md", "report.md", "scope.md", "status.md", "findings.md",
        "export.md", "retest.md", "closeout.md", "notify.md", "deliver.md",
        "run.md", "resume.md", "doctor.md"
    ]
    cmd_dir = ROOT / "commands"
    for f in expected:
        p = cmd_dir / f
        if not p.exists():
            error(f"Missing commands/{f}")
            continue
        fm = _parse_frontmatter(p)
        if fm is None:
            error(f"commands/{f}: missing YAML frontmatter (invisible to runtime)")
        elif "name" not in fm:
            error(f"commands/{f}: frontmatter missing 'name'")
        elif "description" not in fm:
            warn(f"commands/{f}: frontmatter missing 'description'")
        else:
            ok(f"commands/{f}: name={fm['name']}")


def check_skills():
    print("\n=== Skills ===")
    skills_dir = ROOT / "skills"
    total = 0
    no_frontmatter = []
    no_name = []
    no_description = []
    prefixed = []
    for skill_md in sorted(skills_dir.rglob("SKILL.md")):
        total += 1
        category = skill_md.parent.parent.name
        skill_name = skill_md.parent.name
        fm = _parse_frontmatter(skill_md)
        rel = skill_md.relative_to(ROOT)
        if fm is None:
            no_frontmatter.append(str(rel))
            continue
        if "name" not in fm:
            no_name.append(str(rel))
        else:
            name_val = fm["name"]
            if name_val.startswith(f"{category}-"):
                prefixed.append(f"{rel}: name={name_val!r} has category prefix")
        if "description" not in fm:
            no_description.append(str(rel))
    if no_frontmatter:
        for p in no_frontmatter:
            error(f"{p}: missing YAML frontmatter (invisible to runtime)")
    if no_name:
        for p in no_name:
            error(f"{p}: frontmatter missing 'name'")
    if no_description:
        for p in no_description:
            error(f"{p}: frontmatter missing 'description'")
    if prefixed:
        for msg in prefixed:
            warn(msg)
    ok(f"Total skills: {total} ({total - len(no_frontmatter)} with valid frontmatter)")


def check_workflow_skill_refs():
    print("\n=== Workflow skill references ===")
    if yaml is None:
        warn("PyYAML not installed, skipping workflow reference checks")
        return
    skills_dir = ROOT / "skills"
    existing_skills = {p.parent.name for p in skills_dir.rglob("SKILL.md")}
    wf_dir = ROOT / "workflows"
    if not wf_dir.exists():
        error("Missing workflows/ directory")
        return
    for wf_file in sorted(wf_dir.glob("*.yaml")):
        text = wf_file.read_text()
        text_safe = re.sub(r"- \*\s*$", "- __GLOB__", text, flags=re.MULTILINE)
        try:
            data = yaml.safe_load(text_safe)
        except Exception as exc:
            error(f"workflows/{wf_file.name}: YAML parse error: {exc}")
            continue
        unresolved = []
        for phase in data.get("phases", []):
            for key in ("skills", "priority_classes", "secondary_classes",
                        "hunt_classes", "platform_skills"):
                for skill_ref in (phase.get(key) or []):
                    if skill_ref == "__GLOB__":
                        continue
                    if skill_ref not in existing_skills:
                        unresolved.append(skill_ref)
        if unresolved:
            for ref in sorted(set(unresolved)):
                warn(f"workflows/{wf_file.name}: skill '{ref}' not found in skills/")
        else:
            ok(f"workflows/{wf_file.name}: all skill references resolve")


def check_engine():
    print("\n=== Engine ===")
    expected = [
        "__init__.py", "state.py", "scope.py", "findings.py",
        "chain_engine.py", "rebuttal.py", "budget.py",
        "loop_detector.py", "coverage.py", "guard.py",
        "app_profile.py", "brain.py", "vault.py", "router.py",
        "checkpoint.py", "cost_estimator.py", "target_diff.py",
        "oast.py", "sessions.py", "knowledge.py", "custody.py",
        "toolrunner.py", "exporters.py", "timeguard.py", "deliver.py",
        "storage.py", "artifacts.py", "redaction.py", "policy.py", "http_client.py",
        "orchestrator.py", "tool_registry.py", "wordlists.py", "recon_pipeline.py",
        "memory_maintenance.py", "nuclei_templates.py", "nuclei_runner.py",
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
        from engine.oast import OASTManager, OASTToken, Interaction
        ok("engine.oast imports OK")
        from engine.sessions import SessionManager, Session, DiffResult
        ok("engine.sessions imports OK")
        from engine.knowledge import KnowledgeBase, TechniqueRecord
        ok("engine.knowledge imports OK")
        from engine.custody import CustodyLog, CustodyEntry
        ok("engine.custody imports OK")
        from engine.toolrunner import ToolRunner, ToolResult
        ok("engine.toolrunner imports OK")
        from engine.exporters import to_sarif, to_json, to_csv, export
        ok("engine.exporters imports OK")
        from engine.timeguard import TimeWindowGuard, Window
        ok("engine.timeguard imports OK")
        from engine.deliver import build_manifest, verify_manifest, bundle
        ok("engine.deliver imports OK")
        from engine.artifacts import ArtifactStore
        from engine.http_client import ProtectedHTTPClient
        from engine.orchestrator import Orchestrator
        from engine.policy import PolicyEngine
        from engine.storage import read_json, atomic_write_json
        ok("resilience modules import OK")
        from engine.tool_registry import ToolRegistry, CAPABILITY_BACKENDS
        from engine.wordlists import WordlistIndex
        from engine.recon_pipeline import ReconPipeline, Observation
        from engine.memory_maintenance import maintain_knowledge
        from engine.nuclei_templates import NucleiTemplateCatalog
        from engine.nuclei_runner import NucleiRunner
        ok(f"recon/registry/memory/Nuclei modules import OK ({len(CAPABILITY_BACKENDS)} capabilities)")
    except Exception as e:
        error(f"Engine import failed: {e}")


def check_workflows():
    print("\n=== Workflows ===")
    expected = [
        "full-pentest.yaml", "web-app-pentest.yaml", "api-pentest.yaml",
        "cloud-pentest.yaml", "ad-pentest.yaml", "mobile-pentest.yaml",
        "ai-agent-pentest.yaml", "recon-only.yaml",
        "retest.yaml", "pr-scan.yaml",
        "closeout.yaml", "cve-response.yaml", "surface-watch.yaml",
        "purple-team.yaml"
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
    expected = ["full-audit.yaml", "bug-bounty.yaml", "quick-recon.yaml", "ci-scan.yaml"]
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
        "engagement-report.md", "executive-summary.md",
        "critical-alert.md", "closeout-checklist.md"
    ]
    tpl_dir = ROOT / "templates"
    for f in expected:
        p = tpl_dir / f
        if p.exists():
            ok(f"templates/{f}")
        else:
            error(f"Missing templates/{f}")


def check_references():
    print("\n=== References ===")
    expected_root = [
        "cli-rules.md", "anti-fabrication-rules.md", "finding-evidence-standards.md",
        "triage-brocards.md", "tool-backends.md", "cvss4-epss-kev.md"
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

    payloads_dir = ref_dir / "payloads"
    if payloads_dir.exists():
        payloads = list(payloads_dir.glob("*.md"))
        if len(payloads) >= 5:
            ok(f"references/payloads/: {len(payloads)} files")
        else:
            warn(f"references/payloads/ has only {len(payloads)} files")
    else:
        warn("Missing references/payloads/ directory")


def check_benchmarks():
    print("\n=== Benchmarks ===")
    bench = ROOT / "benchmarks"
    if not (bench / "score.py").exists():
        error("Missing benchmarks/score.py")
    else:
        ok("benchmarks/score.py")
    targets = list((bench / "targets").glob("*.yaml")) if (bench / "targets").exists() else []
    if len(targets) >= 2:
        ok(f"benchmarks/targets/: {len(targets)} targets")
    else:
        warn(f"benchmarks/targets/ has only {len(targets)} targets")


def check_nuclei():
    print("\n=== Reviewed Nuclei catalog ===")
    try:
        from engine.nuclei_templates import NucleiTemplateCatalog
        records = NucleiTemplateCatalog().load()["templates"]
        if len(records) >= 40:
            ok(f"Hash-locked Nuclei catalog: {len(records)} reviewed templates")
        else:
            error(f"Nuclei catalog unexpectedly small: {len(records)}")
        if all(item.get("fixture") for item in records):
            ok("Every Nuclei template declares a fixture")
        else:
            error("Nuclei template without fixture metadata")
    except Exception as exc:
        error(f"Nuclei catalog validation failed: {exc}")
    workflows = ["web-app-pentest.yaml", "full-pentest.yaml", "recon-only.yaml",
                 "api-pentest.yaml", "mobile-pentest.yaml", "ai-agent-pentest.yaml"]
    for name in workflows:
        text = (ROOT / "workflows" / name).read_text()
        if "nuclei-reviewed" in text:
            ok(f"{name} integrates reviewed Nuclei")
        else:
            error(f"{name} lacks reviewed Nuclei integration")
    lab = ROOT / "lab" / "nuclei-multistack"
    required = ["docker-compose.yml", "run_lab.py", "README.md", "results.json", "results.md"]
    missing = [name for name in required if not (lab / name).is_file()]
    if missing:
        error(f"Multistack lab missing files: {', '.join(missing)}")
    else:
        ok("Nuclei multistack lab: runner, Compose, docs and results present")
    compose = lab / "docker-compose.yml"
    if compose.is_file():
        if compose.read_text().count("127.0.0.1:") == 6:
            ok("Nuclei multistack lab exposes exactly six loopback-only services")
        else:
            error("Nuclei multistack lab must expose exactly six loopback-only services")


def check_license():
    print("\n=== LICENSE ===")
    p = ROOT / "LICENSE"
    if not p.exists():
        error("Missing LICENSE file")
    else:
        text = p.read_text()
        if "MIT" in text:
            ok("LICENSE file present (MIT)")
        else:
            warn("LICENSE file exists but does not mention MIT")


def check_readme():
    print("\n=== README ===")
    p = ROOT / "README.md"
    if not p.exists():
        error("Missing README.md")
        return
    text = p.read_text()
    checks = [
        ("authorized", "legal disclaimer"),
        ("install", "installation instructions"),
        ("quarry:engage", "quick start"),
        ("benchmark", "benchmark results"),
    ]
    for keyword, label in checks:
        if keyword.lower() in text.lower():
            ok(f"README has {label}")
        else:
            warn(f"README missing {label}")


def check_tests():
    print("\n=== Tests ===")
    for f in ["validate_plugin.py", "test_engine.py", "test_benchmark_score.py",
              "test_resilience.py", "test_recon_capabilities.py", "test_nuclei_capabilities.py",
              "test_nuclei_live_fixtures.py", "test_nuclei_runner_live.py", "nuclei_fixture_server.py"]:
        p = ROOT / "tests" / f
        if p.exists():
            ok(f"tests/{f}")
        else:
            warn(f"Missing tests/{f}")
    ci = ROOT / ".github" / "workflows" / "validate.yml"
    if ci.exists():
        ok(".github/workflows/validate.yml")
    else:
        warn("Missing .github/workflows/validate.yml (CI)")


def main():
    print("=" * 60)
    print("PENTEST PLUGIN VALIDATION")
    print("=" * 60)

    check_plugin_json()
    check_claude_md()
    check_hooks()
    check_license()
    check_readme()
    check_agents()
    check_commands()
    check_skills()
    check_workflow_skill_refs()
    check_engine()
    check_engine_imports()
    check_workflows()
    check_presets()
    check_templates()
    check_references()
    check_benchmarks()
    check_nuclei()
    check_tests()

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
