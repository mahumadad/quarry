#!/usr/bin/env python3
"""Unit tests for reviewed Nuclei policy, selection, execution and evidence."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.app_profile import APIInfo, AppProfile
from engine.artifacts import ArtifactStore
from engine.nuclei_runner import NucleiRunner
from engine.nuclei_templates import NucleiTemplateCatalog, TemplatePolicyError
from engine.policy import PolicyDenied, PolicyEngine
from engine.scope import Scope
from engine.timeguard import TimeWindowGuard
from engine.toolrunner import ToolResult


def authorized_root(host: str = "example.test") -> str:
    root = tempfile.mkdtemp()
    scope = Scope(authorization="signed-test-authorization")
    scope.add_in_scope(host, "domain")
    scope.save(Path(root) / ".pentest-state" / "scope.json")
    TimeWindowGuard(root).configure([], "UTC",
        (datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    return root


def profile(stack: list[str], style: str = "monolith", target: str = "https://example.test") -> AppProfile:
    item = AppProfile(target=target, tech_stack={"frameworks": stack, "backend": stack},
                      api=APIInfo(style="graphql" if "graphql" in stack else "rest"))
    item.architecture.update({"style": style, "frontend_rendering": "spa"})
    if "fintech" in stack or "payment" in stack:
        item.payment_processing = True
    return item


def expect_denied(callback, message: str):
    try:
        callback()
    except (TemplatePolicyError, PolicyDenied):
        return
    raise AssertionError(message)


def test_manifest_complete_and_current():
    manifest = NucleiTemplateCatalog().load()
    records = manifest["templates"]
    assert len(records) == 40
    assert len({item["id"] for item in records}) == 40
    assert all(len(item["sha256"]) == 64 and item["fixture"] for item in records)
    assert all(item["requests"] > 0 for item in records)
    assert not {item["risk"] for item in records} & {"state-changing", "oast"}
    assert sum(item["risk"] == "sensitive-data" for item in records) == 3


def test_hash_tamper_and_unreviewed_addition_fail_closed():
    source = ROOT / "references" / "nuclei-templates"
    parent = Path(tempfile.mkdtemp())
    root = parent / "templates"
    shutil.copytree(source, root)
    catalog = NucleiTemplateCatalog(root)
    catalog.refresh()
    target = root / "python-fastapi-misconfig.yaml"
    target.write_text(target.read_text() + "\n# unreviewed change\n")
    expect_denied(catalog.load, "Modified template did not invalidate manifest")
    catalog.refresh()
    shutil.copy(root / "rails-misconfig.yaml", root / "unreviewed-copy.yaml")
    expect_denied(catalog.load, "Unreviewed addition did not invalidate manifest")


def test_unsafe_template_constructs_rejected():
    source = yaml.safe_load((ROOT / "references" / "nuclei-templates" /
                             "python-fastapi-misconfig.yaml").read_text())
    root = Path(tempfile.mkdtemp()) / "templates"
    root.mkdir(parents=True)

    def reject(mutate):
        data = yaml.safe_load(yaml.safe_dump(source))
        mutate(data)
        path = root / "case.yaml"
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        catalog = NucleiTemplateCatalog(root)
        expect_denied(lambda: catalog.audit(path), "Unsafe construct accepted")

    reject(lambda data: data["http"][0].update({"redirects": True}))
    reject(lambda data: data["http"][0].update({"path": ["{{BaseURL}}:5555/"]}))
    reject(lambda data: data["http"][0].update({"method": "POST"}))
    reject(lambda data: data["http"][0].update({"headers": {"Host": "outside.test"}}))
    reject(lambda data: data["http"][0].update({"headers": {"X-Test": "{{interactsh-url}}"}}))
    reject(lambda data: data["http"][0].update({"matchers": [data["http"][0]["matchers"][0]]}))
    reject(lambda data: data["info"]["metadata"].update({"reviewed": False}))
    reject(lambda data: data.update({"code": []}))


def test_profile_stack_architecture_risk_and_gaps():
    catalog = NucleiTemplateCatalog()
    selected = catalog.select(profile(["python", "fastapi", "graphql", "fintech"]))
    ids = {item["id"] for item in selected["selected"]}
    assert {"fastapi-openapi-documentation", "python-environment-secret-exposed",
            "graphql-introspection", "fintech-openapi-documentation"} <= ids
    assert "fintech-customer-data-exposure" not in ids
    assert "django-debug-exposed" not in ids and "flask-werkzeug-debugger-exposed" not in ids
    assert any(item["id"] == "fintech-customer-data-exposure"
               for item in selected["skipped"])
    sensitive = catalog.select(profile(["fintech"]), "sensitive-data")
    assert "fintech-customer-data-exposure" in {item["id"] for item in sensitive["selected"]}
    next_profile = profile(["nextjs"], style="")
    next_profile.architecture["frontend_rendering"] = ""
    unknown_arch = catalog.select(next_profile)
    assert "nextjs-development-manifest-exposed" not in {item["id"] for item in unknown_arch["selected"]}
    assert any(item["id"] == "nextjs-development-manifest-exposed"
               for item in unknown_arch["skipped"])
    unknown = catalog.select(profile(["mystery-framework"]))
    assert any(item.get("stack") == "mystery-framework" for item in unknown["coverage_gaps"])


def test_scope_ignores_template_filenames():
    command = ("nuclei -u https://example.test -t /tmp/python-env-secret-exposed.yaml "
               "-t relative/graphql.api.yaml -jsonl")
    targets = Scope._extract_targets(command)
    assert "https://example.test" in targets
    assert not any(target.endswith((".yaml", ".yml", ".json", ".txt")) for target in targets), targets


class FakeRunner:
    backend = "local"

    def __init__(self, stdout: str = ""):
        self.stdout = stdout
        self.calls = []

    def is_available(self, tool):
        return tool == "nuclei"

    def run(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        output = "" if "-validate" in argv else self.stdout
        return ToolResult(tool=argv[0], argv=argv, backend="local", exit_code=0, stdout=output)


def test_runner_flags_jsonl_leads_and_artifacts():
    audit = authorized_root()
    lead = json.dumps({"template-id": "fastapi-openapi-documentation",
                       "info": {"name": "docs", "severity": "info"},
                       "host": "example.test", "matched-at": "https://example.test/docs"}) + "\n"
    fake = FakeRunner(lead + lead)  # duplicate JSONL must become one lead
    result = NucleiRunner(audit, runner=fake).run("https://example.test",
        profile(["fastapi", "python"]), "R1", risk="safe")
    assert result["status"] == "completed" and result["lead_count"] == 1
    assert result["leads"][0]["status"] == "lead_requires_independent_validation"
    scan = next(argv for argv, _ in fake.calls if "-u" in argv)
    for flag in ("-dr", "-ni", "-duc", "-jsonl", "-no-stdin"):
        assert flag in scan
    template_paths = [scan[index + 1] for index, value in enumerate(scan[:-1]) if value == "-t"]
    assert template_paths and all(path.endswith(".yaml") for path in template_paths)
    assert any(kwargs.get("is_verification") for _, kwargs in fake.calls)
    assert ArtifactStore(audit).verify()["intact"]
    coverage = json.loads((Path(audit) / ".pentest-state" / "nuclei-coverage.json").read_text())
    assert coverage["runs"][0]["coverage_meaning"].startswith("templates_executed")


def test_scope_and_sensitive_approval_are_enforced():
    audit = authorized_root()
    fake = FakeRunner()
    runner = NucleiRunner(audit, runner=fake)
    expect_denied(lambda: runner.run("https://outside.test", profile(["python"]),
        "R1"), "Out-of-scope target reached runner")
    assert not fake.calls
    target = "https://example.test"
    app = profile(["fintech"])
    plan = runner.plan(target, app, "sensitive-data")
    expect_denied(lambda: runner.run(target, app, "R2", risk="sensitive-data"),
                  "Sensitive profile ran without approval")
    policy = PolicyEngine(audit)
    digest = policy.grant(plan["approval_action"], [target],
        (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())
    result = runner.run(target, app, "R2", risk="sensitive-data", approved_digest=digest)
    assert result["status"] == "completed" and not policy.valid_approval(digest)
    expect_denied(lambda: runner.run(target, app, "R3", risk="sensitive-data",
        approved_digest=digest), "Sensitive approval was reusable")


def test_target_mismatch_and_empty_selection_are_explicit():
    audit = authorized_root()
    fake = FakeRunner()
    runner = NucleiRunner(audit, runner=fake)
    expect_denied(lambda: runner.plan("https://example.test",
        profile(["python"], target="https://other.test")), "Profile target mismatch accepted")
    result = runner.run("https://example.test", AppProfile(target="https://example.test"), "R4")
    assert result["status"] == "no_applicable_templates"
    assert result["coverage_gaps"] and not fake.calls


def main():
    tests = [test_manifest_complete_and_current, test_hash_tamper_and_unreviewed_addition_fail_closed,
             test_unsafe_template_constructs_rejected, test_profile_stack_architecture_risk_and_gaps,
             test_runner_flags_jsonl_leads_and_artifacts, test_scope_and_sensitive_approval_are_enforced,
             test_target_mismatch_and_empty_selection_are_explicit, test_scope_ignores_template_filenames]
    failures = []
    for test in tests:
        try:
            test()
            print(f"  OK: {test.__name__}")
        except Exception as exc:
            failures.append(f"{test.__name__}: {type(exc).__name__}: {exc}")
            print(f"  FAIL: {failures[-1]}")
    print(f"RESULTS: {len(failures)} failures")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
