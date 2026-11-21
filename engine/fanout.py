"""Fan-out/fan-in engine for parallel reconnaissance.

Runs multiple independent recon tasks concurrently, collects results,
deduplicates, and correlates. Budget-aware: checks remaining budget
before launching each task.
"""
from __future__ import annotations

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

try:
    from .pacing import apply_to_command
    from .policy import PolicyDenied, _find_engagement_dir, command_policy
except ImportError:  # top-level script mode
    from pacing import apply_to_command
    from policy import PolicyDenied, _find_engagement_dir, command_policy


@dataclass
class ReconTask:
    name: str
    command: str
    timeout: int = 120
    parser: Callable[[str], list[str]] | None = None
    phase: str = "recon"


@dataclass
class TaskResult:
    name: str
    command: str
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    parsed: list[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    duration_ms: int = 0
    output_size: int = 0
    error: str = ""

    def __post_init__(self):
        if not self.start_time:
            self.start_time = datetime.now(timezone.utc).isoformat()


RECON_PRESETS: dict[str, list[dict]] = {
    "subdomain-discovery": [
        {"name": "subfinder", "command": "subfinder -d {target} -silent", "timeout": 120},
        {"name": "amass-passive", "command": "amass enum -passive -d {target}", "timeout": 300},
        {"name": "assetfinder", "command": "assetfinder --subs-only {target}", "timeout": 60},
    ],
    "http-probe": [
        {"name": "httpx", "command": "echo '{target}' | httpx -silent -status-code -title", "timeout": 60},
    ],
    "port-scan": [
        {"name": "nmap-top", "command": "nmap -sT --top-ports 1000 -T4 {target} -oX -", "timeout": 300},
    ],
    "tech-fingerprint": [
        {"name": "whatweb", "command": "whatweb -q {target}", "timeout": 60},
    ],
    "content-discovery": [
        {"name": "ffuf", "command": "ffuf -u https://{target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -s", "timeout": 180},
    ],
    "secret-scan": [
        {"name": "gitleaks", "command": "gitleaks detect --source {target} --no-git -r /dev/stdout", "timeout": 120},
    ],
}


def _default_line_parser(output: str) -> list[str]:
    return [line.strip() for line in output.strip().split("\n") if line.strip()]


class FanOutEngine:
    def __init__(self, max_workers: int = 5, budget_manager: Any = None,
                 audit_dir: str | None = None, pacing: str = "off"):
        self.max_workers = max_workers
        self._budget = budget_manager
        # Operator-chosen aggression profile. "off" (default) injects nothing,
        # so recon fires at the presets' own speed, exactly as before.
        self.pacing = pacing
        # Engagement root for the scope tripwire. Inside an engagement every
        # recon command is validated against scope before it runs — fan-out
        # must not be a side door around the same check the sync runner and
        # async runner enforce.
        self._audit_dir = str(audit_dir) if audit_dir else os.getcwd()

    def _finish(self, result: TaskResult) -> TaskResult:
        result.end_time = datetime.now(timezone.utc).isoformat()
        return result

    def _run_task(self, task: ReconTask) -> TaskResult:
        result = TaskResult(name=task.name, command=task.command)

        if self._budget:
            budget_check = self._budget.record_call(task.phase, task.command)
            if not budget_check.get("allowed"):
                result.error = "Budget exhausted"
                return self._finish(result)

        # Scope gate BEFORE spawning the process. No-op outside an engagement
        # (same as the PreToolUse hook); inside one, an out-of-scope recon
        # target is blocked, and an engine failure fails closed.
        if _find_engagement_dir(self._audit_dir) is not None:
            try:
                command_policy(task.command, self._audit_dir)
            except PolicyDenied as exc:
                result.error = "policy: {}".format(exc)
                return self._finish(result)
            except Exception as exc:  # fail closed
                result.error = "policy engine failure; fail-closed: {}: {}".format(
                    type(exc).__name__, exc)
                return self._finish(result)

        try:
            proc = subprocess.run(
                task.command, shell=True, capture_output=True,
                text=True, timeout=task.timeout,
            )
            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
            result.output_size = len(proc.stdout) + len(proc.stderr)

            parser = task.parser or _default_line_parser
            result.parsed = parser(proc.stdout)

        except subprocess.TimeoutExpired:
            result.error = f"Timeout after {task.timeout}s"
        except OSError as exc:
            result.error = str(exc)

        result.end_time = datetime.now(timezone.utc).isoformat()
        if result.start_time and result.end_time:
            start = datetime.fromisoformat(result.start_time)
            end = datetime.fromisoformat(result.end_time)
            result.duration_ms = int((end - start).total_seconds() * 1000)
        return result

    def fan_out(self, tasks: list[ReconTask]) -> list[TaskResult]:
        results: list[TaskResult] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._run_task, t): t for t in tasks}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    task = futures[future]
                    results.append(TaskResult(
                        name=task.name, command=task.command,
                        error=f"Executor error: {exc}",
                        end_time=datetime.now(timezone.utc).isoformat(),
                    ))
        return results

    @staticmethod
    def fan_in(results: list[TaskResult]) -> dict:
        all_items: list[str] = []
        errors: list[dict] = []

        for r in results:
            if r.error:
                errors.append({"task": r.name, "error": r.error})
            else:
                all_items.extend(r.parsed)

        unique = sorted(set(all_items))
        return {
            "merged_at": datetime.now(timezone.utc).isoformat(),
            "total_raw": len(all_items),
            "unique": len(unique),
            "duplicates_removed": len(all_items) - len(unique),
            "items": unique,
            "errors": errors,
            "tasks_completed": len([r for r in results if not r.error]),
            "tasks_failed": len(errors),
        }

    def recon_blast(self, target: str,
                    techniques: list[str] | None = None) -> dict:
        """Run a preset combination of recon tasks against a target."""
        techniques = techniques or list(RECON_PRESETS.keys())
        tasks = []
        for tech in techniques:
            presets = RECON_PRESETS.get(tech, [])
            for p in presets:
                command = p["command"].replace("{target}", target)
                command = apply_to_command(command, self.pacing)
                tasks.append(ReconTask(
                    name=p["name"],
                    command=command,
                    timeout=p.get("timeout", 120),
                ))

        results = self.fan_out(tasks)
        merged = self.fan_in(results)
        merged["target"] = target
        merged["techniques"] = techniques
        merged["task_details"] = [
            {"name": r.name, "exit_code": r.exit_code,
             "duration_ms": r.duration_ms, "output_size": r.output_size,
             "items_found": len(r.parsed), "error": r.error}
            for r in results
        ]
        return merged


def main() -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        prog="engine.fanout",
        description="Parallel recon fan-out (scope-gated inside an engagement).")
    ap.add_argument("--audit-dir", default=".")
    ap.add_argument("--target", required=True)
    ap.add_argument("--techniques", default="",
                    help="comma-separated preset names; default = all. "
                         "Available: {}".format(", ".join(RECON_PRESETS)))
    ap.add_argument("--max-workers", type=int, default=5)
    ap.add_argument("--pacing", default="off",
                    help="noise governor: off (default), quiet, balanced, "
                         "aggressive — per-host rate ceiling injected into "
                         "each recon command")
    args = ap.parse_args()

    techniques = [t.strip() for t in args.techniques.split(",") if t.strip()] or None
    engine = FanOutEngine(max_workers=args.max_workers, audit_dir=args.audit_dir,
                          pacing=args.pacing)
    merged = engine.recon_blast(args.target, techniques)
    print(json.dumps(merged, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
