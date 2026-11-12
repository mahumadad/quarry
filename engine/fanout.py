"""Fan-out/fan-in engine for parallel reconnaissance.

Runs multiple independent recon tasks concurrently, collects results,
deduplicates, and correlates. Budget-aware: checks remaining budget
before launching each task.
"""
from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


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
    def __init__(self, max_workers: int = 5, budget_manager: Any = None):
        self.max_workers = max_workers
        self._budget = budget_manager

    def _run_task(self, task: ReconTask) -> TaskResult:
        result = TaskResult(name=task.name, command=task.command)

        if self._budget:
            budget_check = self._budget.record_call(task.phase, task.command)
            if not budget_check.get("allowed"):
                result.error = "Budget exhausted"
                result.end_time = datetime.now(timezone.utc).isoformat()
                return result

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
                tasks.append(ReconTask(
                    name=p["name"],
                    command=p["command"].replace("{target}", target),
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
