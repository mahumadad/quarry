"""Fail-closed execution of the reviewed local Nuclei template catalog."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .app_profile import AppProfile, AppProfileStore
    from .artifacts import ArtifactStore
    from .nuclei_templates import NucleiTemplateCatalog, RISK_PROFILES, TemplatePolicyError
    from .policy import PolicyEngine, canonical_url_target
    from .redaction import redact
    from .storage import atomic_write_json, engagement_lock, read_json
    from .tool_registry import ToolRegistry
    from .toolrunner import ToolRunner, ToolResult
except ImportError:
    from app_profile import AppProfile, AppProfileStore
    from artifacts import ArtifactStore
    from nuclei_templates import NucleiTemplateCatalog, RISK_PROFILES, TemplatePolicyError
    from policy import PolicyEngine, canonical_url_target
    from redaction import redact
    from storage import atomic_write_json, engagement_lock, read_json
    from tool_registry import ToolRegistry
    from toolrunner import ToolRunner, ToolResult


class NucleiRunner:
    def __init__(self, audit_dir: str | Path, catalog: NucleiTemplateCatalog | None = None,
                 runner: ToolRunner | None = None):
        self.audit_dir = Path(audit_dir)
        self.catalog = catalog or NucleiTemplateCatalog()
        self.runner = runner or ToolRunner(str(audit_dir))
        self.coverage_file = self.audit_dir / ".pentest-state" / "nuclei-coverage.json"

    @staticmethod
    def _action(target: str, risk: str, selected: list[dict]) -> str:
        ids = ",".join(sorted(item["id"] for item in selected))
        return f"nuclei-reviewed-scan risk={risk} target={target} templates={ids}"

    def plan(self, target: str, profile: AppProfile | dict[str, Any], risk: str = "safe") -> dict:
        target = canonical_url_target(target)
        selection = self.catalog.select(profile, risk)
        profile_target = selection.get("profile_target")
        if profile_target:
            old, new = urlsplit(profile_target), urlsplit(target)
            if (old.scheme.lower(), (old.hostname or "").lower(), old.port) != (
                    new.scheme.lower(), (new.hostname or "").lower(), new.port):
                raise TemplatePolicyError("AppProfile target does not match scan target")
        selection["target"] = target
        selection["approval_action"] = self._action(target, risk, selection["selected"])
        selection["requires_operator_approval"] = risk not in {"safe", "authenticated"}
        return selection

    def _validate_offline(self, selected: list[dict], run_id: str, task_id: str) -> ToolResult:
        argv = ["nuclei", "-validate", "-duc", "-no-stdin"]
        for record in selected:
            argv.extend(["-t", str(self.catalog.root / record["path"])])
        result = self.runner.run(argv, timeout=120, is_verification=True,
                                 run_id=run_id, task_id=f"{task_id}-validate")
        if result.exit_code != 0:
            raise TemplatePolicyError(f"Nuclei validation failed: {result.stderr[-1000:]}")
        # Detect a template changed between manifest selection and validation.
        self.catalog.load(verify_hashes=True)
        return result

    @staticmethod
    def _leads(stdout: str) -> tuple[list[dict], int]:
        leads, malformed, seen = [], 0, set()
        for line in stdout.splitlines():
            if not line.strip().startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            info = item.get("info") or {}
            template_id = item.get("template-id", item.get("template_id", ""))
            matched_at = item.get("matched-at", item.get("matched_at", ""))
            key = (template_id, item.get("host", ""), matched_at)
            if key in seen:
                continue
            seen.add(key)
            leads.append({
                "template_id": template_id,
                "name": info.get("name", ""),
                "severity": info.get("severity", "unknown"),
                "host": item.get("host", ""),
                "matched_at": matched_at,
                "timestamp": item.get("timestamp", ""),
                "status": "lead_requires_independent_validation",
            })
        return leads, malformed

    def _persist(self, record: dict) -> None:
        with engagement_lock(self.audit_dir):
            data = read_json(self.coverage_file, {"schema_version": 1, "runs": []})
            data.setdefault("runs", []).append(redact(record))
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            atomic_write_json(self.coverage_file, data)

    def run(self, target: str, profile: AppProfile | dict[str, Any], run_id: str,
            task_id: str = "nuclei", risk: str = "safe", approved_digest: str = "",
            rate_limit: int = 5, concurrency: int = 2, bulk_size: int = 1,
            timeout: int = 300) -> dict[str, Any]:
        if self.runner.backend != "local":
            raise TemplatePolicyError("Reviewed local template paths require the local backend")
        if not 1 <= rate_limit <= 100 or not 1 <= concurrency <= 25 or not 1 <= bulk_size <= 25:
            raise ValueError("Rate/concurrency/bulk limits outside safe bounds")
        plan = self.plan(target, profile, risk)
        selected = plan["selected"]
        if not selected:
            result = {**plan, "status": "no_applicable_templates", "leads": []}
            self._persist(result)
            return result
        target = plan["target"]
        dangerous = plan["requires_operator_approval"]
        PolicyEngine(self.audit_dir).authorize(plan["approval_action"], [target],
                                               dangerous=dangerous,
                                               approved_digest=approved_digest)
        self._validate_offline(selected, run_id, task_id)
        probe = ToolRegistry(self.audit_dir, runner=self.runner).probe("nuclei")
        argv = ["nuclei", "-u", target, "-jsonl", "-silent", "-nc", "-dr", "-ni",
                "-duc", "-no-stdin", "-pt", "http", "-rl", str(rate_limit),
                "-c", str(concurrency), "-bs", str(bulk_size), "-retries", "0",
                "-mhe", "5", "-timeout", "10"]
        for record in selected:
            argv.extend(["-t", str(self.catalog.root / record["path"])])
        execution = self.runner.run(argv, timeout=timeout, run_id=run_id,
                                    task_id=f"{task_id}-scan")
        if dangerous:
            PolicyEngine(self.audit_dir).consume(approved_digest)
        store = ArtifactStore(self.audit_dir)
        store.capture(run_id, f"{task_id}-evidence", "nuclei.jsonl", execution.stdout,
                      content_type="application/x-ndjson", complete=not execution.timed_out,
                      metadata={"template_ids": [item["id"] for item in selected],
                                "template_hashes": {item["id"]: item["sha256"] for item in selected},
                                "engine": probe})
        leads, malformed = self._leads(execution.stdout)
        status = "timed_out" if execution.timed_out else "completed" if execution.exit_code == 0 else "failed"
        result = {
            **plan,
            "status": status,
            "coverage_meaning": "templates_executed; zero leads is not proof of absence",
            "engine": probe,
            "exit_code": execution.exit_code,
            "timed_out": execution.timed_out,
            "leads": leads,
            "lead_count": len(leads),
            "malformed_jsonl_lines": malformed,
            "ran_at": execution.ran_at,
        }
        store.capture(run_id, f"{task_id}-evidence", "coverage.json",
                      json.dumps(redact(result), indent=2, ensure_ascii=False),
                      content_type="application/json")
        self._persist(result)
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run reviewed Nuclei checks with scope and risk gates")
    parser.add_argument("--audit-dir", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--task-id", default="nuclei")
    parser.add_argument("--risk", default="safe", choices=sorted(RISK_PROFILES))
    parser.add_argument("--approved-digest", default="")
    parser.add_argument("--rate-limit", type=int, default=5)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    profile = AppProfileStore(args.audit_dir).get()
    if profile is None:
        parser.error("No AppProfile exists for this engagement")
    runner = NucleiRunner(args.audit_dir)
    result = (runner.plan(args.target, profile, args.risk) if args.plan_only else
              runner.run(args.target, profile, args.run_id, args.task_id, args.risk,
                         args.approved_digest, args.rate_limit, args.concurrency))
    print(json.dumps(redact(result), indent=2, ensure_ascii=False))
    return 0 if result.get("status", "planned") in {"planned", "completed", "no_applicable_templates"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
