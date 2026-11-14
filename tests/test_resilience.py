#!/usr/bin/env python3
"""Regression tests for fail-closed policy, durable runs and secret hygiene."""
import json
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.artifacts import ArtifactStore
from engine.coverage import CoverageTracker
from engine.custody import CustodyLog
from engine.orchestrator import Orchestrator
from engine.policy import PolicyDenied, PolicyEngine, approval_digest, command_policy
from engine.scope import Scope
from engine.sessions import Session, SessionManager
from engine.state import EngagementState, Phase
from engine.storage import StateCorruptionError, read_json
from engine.timeguard import TimeWindowGuard
from engine.vault import Vault


def authorized_root() -> str:
    root = tempfile.mkdtemp()
    scope = Scope(authorization="signed-test-authorization")
    scope.add_in_scope("example.test", "domain")
    scope.add_out_of_scope("https://example.test/admin", "url")
    scope.save(Path(root) / ".pentest-state" / "scope.json")
    TimeWindowGuard(root).configure([], "UTC",
        (datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    return root


def test_fail_closed_policy():
    root = authorized_root()
    assert command_policy("curl https://example.test/api", root)["allowed"]
    try:
        command_policy("curl https://outside.test", root)
        raise AssertionError("out-of-scope command was allowed")
    except PolicyDenied:
        pass
    assert not Scope.load(Path(root) / ".pentest-state" / "scope.json").is_in_scope(
        "https://example.test/admin/users")
    # No engagement here (no .pentest-state/): the guard is a no-op, not fail-closed.
    empty = tempfile.mkdtemp()
    assert command_policy("curl https://example.test", empty)["allowed"]
    # But an engagement dir with no scope.json still fails closed.
    noscope = tempfile.mkdtemp()
    (Path(noscope) / ".pentest-state").mkdir()
    try:
        command_policy("curl https://example.test", noscope)
        raise AssertionError("engagement without scope was fail-open")
    except PolicyDenied:
        pass


def test_scoped_single_use_approval():
    root = authorized_root()
    policy = PolicyEngine(root)
    action = "sqlmap --os-shell https://example.test"
    targets = ["https://example.test"]
    digest = policy.grant(action, targets,
        (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())
    assert digest == approval_digest(action, "\n".join(targets))
    policy.authorize(action, targets, dangerous=True, approved_digest=digest)
    policy.consume(digest)
    try:
        policy.authorize(action, targets, dangerous=True, approved_digest=digest)
        raise AssertionError("approval was reusable")
    except PolicyDenied:
        pass


def test_artifacts_and_coverage():
    root = tempfile.mkdtemp()
    artifact = ArtifactStore(root).capture("R1", "T1", "response.http",
        "authorization: Bearer secret-token\n\nfull-body")
    assert artifact.size > 5000 or artifact.size > 0
    assert artifact.sha256
    view = (Path(root) / artifact.redacted_path).read_text()
    assert "secret-token" not in view and "[REDACTED]" in view
    coverage = CoverageTracker(root)
    coverage.add_surface("example.test", "/api", "post", ["id"], ["user-a"], ["idor"])
    try:
        coverage.mark_tested("example.test", "idor", endpoint="/api", method="POST",
            parameter="id", identity="user-a")
        raise AssertionError("clean status accepted without evidence")
    except ValueError:
        pass
    coverage.mark_tested("example.test", "idor", endpoint="/api", method="POST",
        parameter="id", identity="user-a", evidence_artifacts=[artifact.artifact_id],
        evidence_complete=True)
    assert CoverageTracker(root).summary()["tested"] == 1


def test_encrypted_vault_and_sessions():
    root = tempfile.mkdtemp()
    Vault(root).store("test", "password", "very-secret-value")
    raw = (Path(root) / ".pentest-state" / "vault.json").read_text()
    assert "very-secret-value" not in raw and "fernet" in raw
    sessions = SessionManager(root)
    sessions.register(Session(name="a", cookies={"session": "cookie-secret"}))
    metadata = (Path(root) / ".pentest-state" / "sessions.json").read_text()
    assert "cookie-secret" not in metadata
    assert SessionManager(root).get("a").cookies["session"] == "cookie-secret"


def test_orchestrator_resume_and_state():
    root = tempfile.mkdtemp()
    workflow = Path(root) / "workflow.json"
    workflow.write_text(json.dumps({"name": "test", "phases": [
        {"name": "recon", "skills": ["one"]},
        {"name": "mapping", "skills": ["two"]}]}))
    engagement = EngagementState(root)
    engagement.initialize("E1", "example.test")
    engagement.transition(Phase.SCOPED)
    orchestrator = Orchestrator(root)
    record = orchestrator.create_run(workflow)
    finished = orchestrator.run(record["run_id"], lambda task, context: {"observed": task.skill})
    assert finished["status"] == "completed"
    assert EngagementState(root).phase == Phase.MAPPED
    assert orchestrator.resume_plan(record["run_id"])["pending_count"] == 0
    crashed = orchestrator.create_run(workflow)
    task = crashed["tasks"][0]
    orchestrator.update_task(task["task_id"], status="running")
    assert orchestrator.recover_interrupted(crashed["run_id"]) == [task["task_id"]]
    assert orchestrator.resume_plan(crashed["run_id"])["interrupted"] == 1


def test_concurrent_custody_and_corruption():
    root = tempfile.mkdtemp()
    def append(index):
        CustodyLog(root).append("note", {"index": index})
    threads = [threading.Thread(target=append, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result = CustodyLog(root).verify()
    assert result["intact"] and result["entries"] == 12
    path = Path(root) / ".pentest-state" / "broken.json"
    path.write_text("{")
    try:
        read_json(path)
        raise AssertionError("corrupt JSON was silently accepted")
    except StateCorruptionError:
        pass


def main():
    tests = [test_fail_closed_policy, test_scoped_single_use_approval,
             test_artifacts_and_coverage, test_encrypted_vault_and_sessions,
             test_orchestrator_resume_and_state, test_concurrent_custody_and_corruption]
    failures = []
    for test in tests:
        try:
            test()
            print(f"  OK: {test.__name__}")
        except Exception as exc:
            failures.append(f"{test.__name__}: {exc}")
            print(f"  FAIL: {failures[-1]}")
    print(f"RESULTS: {len(failures)} failures")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
