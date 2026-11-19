"""Reference executor dispatch + a real orchestrator.run integration.

Freezes that mechanizable tasks (recon) are executed by the engine while
cognitive tasks (hunting) are skipped for the agent, and that an end-to-end
orchestrator run with this executor advances to 'completed' instead of
falling back to resume_plan and doing nothing. Tool entry points are
injected so no real recon/scan binary runs.
"""
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.executor import ReferenceExecutor  # noqa: E402
from engine.orchestrator import Orchestrator, Task  # noqa: E402
from engine.timeguard import TimeWindowGuard  # noqa: E402


@pytest.fixture()
def engagement(tmp_path):
    state = tmp_path / ".pentest-state"
    state.mkdir()
    (state / "scope.json").write_text(json.dumps({
        "in_scope": [{"pattern": "target.example.com", "type": "domain"}],
        "out_of_scope": [],
        "authorization": "signed RoE",
    }))
    TimeWindowGuard(str(tmp_path)).configure(
        windows=[], timezone="UTC",
        expires_at="2027-01-01T00:00:00+00:00")
    return tmp_path


def _task(**kw):
    base = dict(task_id="t1", run_id="r1", phase="recon", skill="subdomain-discovery")
    base.update(kw)
    return Task(**base)


def test_recon_task_dispatched_to_engine(engagement):
    seen = {}

    def fake_recon(target, techniques):
        seen["target"] = target
        seen["techniques"] = techniques
        return {"items": ["a.target.example.com"], "unique": 1, "errors": []}

    ex = ReferenceExecutor(str(engagement), recon_fn=fake_recon)
    res = ex(_task(), {})
    assert res["status"] == "completed"
    assert res["executed_by"] == "engine"
    assert seen["target"] == "target.example.com"  # fell back to scope
    assert seen["techniques"] == ["subdomain-discovery"]


def test_cognitive_task_skipped_for_agent(engagement):
    ex = ReferenceExecutor(str(engagement))
    res = ex(_task(phase="hunting", skill="sqli"), {})
    assert res["status"] == "skipped"
    assert res["executed_by"] == "agent"


def test_recon_without_any_target_skipped(tmp_path):
    # No scope.json -> no scope target, and no asset on the task.
    (tmp_path / ".pentest-state").mkdir()
    ex = ReferenceExecutor(str(tmp_path))
    res = ex(_task(), {})
    assert res["status"] == "skipped"


def test_tool_exception_fails_closed(engagement):
    def boom(target, techniques):
        raise RuntimeError("tool blew up")

    ex = ReferenceExecutor(str(engagement), recon_fn=boom)
    res = ex(_task(), {})
    assert res["status"] == "failed"
    assert "tool blew up" in res["error"]


def test_verify_task_runs_three_gate_when_spec_present(engagement):
    captured = {}

    def fake_verify(finding_id, args):
        captured["finding_id"] = finding_id
        captured["args"] = args
        return {"verdict": "confirmed"}

    ex = ReferenceExecutor(str(engagement), verify_fn=fake_verify)
    task = _task(phase="validation", skill="finding-validation")
    res = ex(task, {"verify_spec": {"finding_id": "F-1",
                                    "baseline_url": "http://target.example.com/"}})
    assert res["status"] == "completed"
    assert res["result"]["verdict"] == "confirmed"
    assert captured["finding_id"] == "F-1"
    assert "finding_id" not in captured["args"]


def test_orchestrator_run_end_to_end(engagement):
    wf = engagement / "wf.yaml"
    wf.write_text(
        "name: tiny\n"
        "phases:\n"
        "  - name: recon\n"
        "    skills: [subdomain-discovery]\n"
        "  - name: hunting\n"
        "    skills: [sqli]\n"
    )
    orch = Orchestrator(str(engagement))
    run = orch.create_run(str(wf))
    ex = ReferenceExecutor(
        str(engagement),
        recon_fn=lambda t, techs: {"items": [], "unique": 0, "errors": []})
    final = orch.run(run["run_id"], executor=ex)
    statuses = {t["skill"]: t["status"] for t in final["tasks"]}
    assert statuses["subdomain-discovery"] == "completed"
    assert statuses["sqli"] == "skipped"
    assert final["status"] == "completed"
