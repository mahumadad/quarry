"""Reference executor for the orchestrator.

``Orchestrator.run`` takes an ``executor(task, context) -> result`` callback
but the repo shipped none, so a scripted run fell back to ``resume_plan`` and
did nothing. This is that callback: it mechanizes the deterministic tasks —
recon fan-out, reviewed Nuclei scans, and 3-gate verification — and returns
``skipped`` for cognitive tasks (hunting, mapping, reporting), which the LLM
agent performs.

Autonomy: mechanizable tasks fire without a human pause. The scope + single-
use-approval gate is NOT bypassed — it lives inside the engine calls this
dispatches to (``FanOutEngine`` → ``command_policy``, ``NucleiRunner`` /
``ProtectedHTTPClient`` → ``PolicyEngine``), so an out-of-scope or unapproved
action is still refused.

Tool entry points are injected so the dispatch logic is testable without
running real recon/scan binaries or reaching the network.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

try:
    from .fanout import FanOutEngine
    from .three_gate import verify_and_record
except ImportError:  # top-level script mode
    from fanout import FanOutEngine
    from three_gate import verify_and_record


# Recon skill (directory name) -> fan-out preset technique.
RECON_SKILL_TECHNIQUE = {
    "subdomain-discovery": "subdomain-discovery",
    "subdomain-enumeration": "subdomain-discovery",
    "dns-enumeration": "subdomain-discovery",
    "port-scan": "port-scan",
    "service-enumeration": "port-scan",
    "tech-stack-fingerprint": "tech-fingerprint",
    "surface-probes": "http-probe",
    "active-recon": "http-probe",
    "web-crawling": "content-discovery",
}
SCAN_SKILLS = {"nuclei-reviewed", "nuclei"}


class ReferenceExecutor:
    """Callable ``(task, context) -> result`` for ``Orchestrator.run``."""

    def __init__(self, audit_dir: str,
                 recon_fn: Callable[[str, list[str]], dict] | None = None,
                 nuclei_fn: Callable[[str, dict], dict] | None = None,
                 verify_fn: Callable[[str, dict], Any] | None = None):
        self.audit_dir = str(audit_dir)
        self._recon_fn = recon_fn
        self._nuclei_fn = nuclei_fn
        self._verify_fn = verify_fn

    # -- dispatch ---------------------------------------------------------

    def __call__(self, task: Any, context: dict) -> dict:
        skill = getattr(task, "skill", "") or ""
        phase = getattr(task, "phase", "") or ""
        try:
            if phase == "recon" and skill in RECON_SKILL_TECHNIQUE:
                return self._run_recon(task)
            if skill in SCAN_SKILLS:
                return self._run_scan(task, context)
            spec = (context or {}).get("verify_spec")
            if phase == "validation" and spec:
                return self._run_verify(task, spec)
        except Exception as exc:  # fail closed: a tool error is not a silent pass
            return {"status": "failed",
                    "error": "{}: {}".format(type(exc).__name__, exc)}
        return {"status": "skipped",
                "reason": "requires agent: {}/{}".format(phase, skill),
                "executed_by": "agent"}

    # -- mechanizable actions --------------------------------------------

    def _scope_target(self) -> str:
        """First in-scope asset, used when a task carries none (recon tasks
        from the orchestrator get their target from scope, not the cell)."""
        scope_file = Path(self.audit_dir) / ".pentest-state" / "scope.json"
        try:
            data = json.loads(scope_file.read_text())
        except (OSError, ValueError):
            return ""
        for item in data.get("in_scope", []):
            pattern = (item.get("pattern") or "").strip()
            if pattern and "*" not in pattern:
                return pattern
        return ""

    def _target(self, task: Any) -> str:
        explicit = (getattr(task, "asset", "") or getattr(task, "endpoint", "")).strip()
        return explicit or self._scope_target()

    def _run_recon(self, task: Any) -> dict:
        target = self._target(task)
        if not target:
            return {"status": "skipped", "reason": "recon task has no asset/endpoint",
                    "executed_by": "agent"}
        technique = RECON_SKILL_TECHNIQUE[task.skill]
        recon = self._recon_fn or (
            lambda t, techs: FanOutEngine(audit_dir=self.audit_dir).recon_blast(t, techs))
        merged = recon(target, [technique])
        # A policy block surfaces as per-task errors inside the merged result;
        # the recon still "ran" (nothing out of scope was executed).
        return {"status": "completed", "executed_by": "engine",
                "outputs": merged.get("items", []),
                "result": {"technique": technique, "target": target,
                           "unique": merged.get("unique", 0),
                           "errors": merged.get("errors", [])}}

    def _run_scan(self, task: Any, context: dict) -> dict:
        target = self._target(task)
        if not target:
            return {"status": "skipped", "reason": "scan task has no asset/endpoint",
                    "executed_by": "agent"}
        if self._nuclei_fn is None:
            # No injected runner and no profile in context: hand to the agent
            # rather than guess scan parameters.
            return {"status": "skipped",
                    "reason": "nuclei scan needs an app profile; agent to run",
                    "executed_by": "agent"}
        result = self._nuclei_fn(target, context or {})
        status = result.get("status", "completed")
        completed = status in {"completed", "timed_out", "no_applicable_templates"}
        return {"status": "completed" if completed else "failed",
                "executed_by": "engine",
                "result": {"lead_count": result.get("lead_count", 0),
                           "scan_status": status}}

    def _run_verify(self, task: Any, spec: dict) -> dict:
        verify = self._verify_fn or (
            lambda fid, s: verify_and_record(self.audit_dir, fid, **s))
        finding_id = spec.get("finding_id", "")
        verify_args = {k: v for k, v in spec.items() if k != "finding_id"}
        verdict = verify(finding_id, verify_args)
        vlabel = getattr(verdict, "verdict", None) or (
            verdict.get("verdict") if isinstance(verdict, dict) else "unknown")
        return {"status": "completed", "executed_by": "engine",
                "result": {"finding_id": finding_id, "verdict": vlabel}}
