#!/usr/bin/env python3
"""Tests for recon handoffs, reproducible capabilities and retention."""
import json
import sys
import tarfile
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.artifacts import ArtifactStore
from engine.deliver import bundle
from engine.http_client import ProtectedHTTPClient
from engine.memory_maintenance import maintain_knowledge
from engine.orchestrator import Orchestrator
from engine.policy import PolicyDenied, PolicyEngine
from engine.recon_pipeline import Observation, ReconPipeline
from engine.router import Router
from engine.scope import Scope
from engine.timeguard import TimeWindowGuard
from engine.tool_registry import ToolRegistry
from engine.wordlists import WordlistIndex


def authorized_root() -> str:
    root = tempfile.mkdtemp()
    scope = Scope(authorization="signed-test-authorization")
    scope.add_in_scope("example.test", "domain")
    scope.save(Path(root) / ".pentest-state" / "scope.json")
    TimeWindowGuard(root).configure([], "UTC",
        (datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    return root


def test_tool_registry_fallback_and_gap():
    class FakeRunner:
        backend = "local"
        def is_available(self, tool):
            return tool == "curl"

    root = tempfile.mkdtemp()
    registry = ToolRegistry(root, runner=FakeRunner(), version_detector=lambda tool: "curl test 1.0")
    selected = registry.select("http-probe")
    assert selected["selected"]["tool"] == "curl"
    assert selected["selected"]["version"] == "curl test 1.0"
    missing = registry.select("template-scan")
    assert missing["status"] == "tool_unavailable" and missing["selected"] is None
    assert "template-scan" in registry.load()["unavailable"]


def test_wordlist_reproducibility():
    audit = tempfile.mkdtemp()
    lists = Path(tempfile.mkdtemp())
    (lists / "web-php.txt").write_text("admin\nlogin\n")
    (lists / "api-routes.txt").write_text("users\ninvoices\n")
    index = WordlistIndex(audit)
    records = index.scan([lists])
    assert len(records) == 2 and all(len(item["sha256"]) == 64 for item in records)
    first = index.select("content-discovery", "php", run_id="R1", task_id="T1")
    second = index.select("web", "php", run_id="R1", task_id="T2")
    assert first["selected"]["sha256"] == second["selected"]["sha256"]
    assert first["selected"]["path"].endswith("web-php.txt")
    saved = json.loads((Path(audit) / ".pentest-state" / "wordlists.json").read_text())
    assert len(saved["selections"]) == 2


def test_recon_dedup_scope_provenance_and_ranking():
    root = authorized_root()
    pipeline = ReconPipeline(root)
    result = pipeline.ingest([
        Observation("host", "WWW.EXAMPLE.TEST.", "crt.sh", "passive",
                    metadata={"forgotten": True, "legacy": True}),
        Observation("host", "www.example.test", "subfinder", "dns"),
        Observation("url", "https://www.example.test:443/import?b=2&a=1", "katana", "crawl",
                    metadata={"import_export": True, "sensitive_function": True}),
        Observation("url", "https://www.example.test/import?a=1&b=2", "gau", "history"),
        Observation("host", "outside.test", "crt.sh", "passive"),
    ])
    assert result["stats"]["new"] == 3
    assert result["stats"]["merged"] == 2
    assert result["stats"]["out_of_scope"] == 1
    data = json.loads((Path(root) / ".pentest-state" / "recon-inventory.json").read_text())
    host = next(item for item in data["records"] if item["value"] == "www.example.test")
    assert len(host["provenance"]) == 2
    assert result["ranked_assets"][0]["priority_score"] >= 16
    outside = next(item for item in data["records"] if item["value"] == "outside.test")
    assert outside["status"] == "out_of_scope_pending_authorization"
    artifact = pipeline.save_artifact("R1")
    assert artifact.sha256 and artifact.metadata["record_count"] == 3


def test_memory_retention_archives_before_pruning():
    root = Path(tempfile.mkdtemp())
    path = root / "knowledge.json"
    now = datetime.now(timezone.utc)
    records = [
        {"technique": "old", "last_seen": (now - timedelta(days=400)).isoformat(), "times_seen": 1},
        {"technique": "recent", "last_seen": now.isoformat(), "times_seen": 2},
        {"technique": "overflow", "last_seen": (now - timedelta(days=2)).isoformat(), "times_seen": 1},
    ]
    path.write_text(json.dumps({"records": records}))
    result = maintain_knowledge(path, max_records=1, max_age_days=365, now=now)
    assert result["before"] == 3 and result["after"] == 1 and result["archived"] == 2
    active = json.loads(path.read_text())["records"]
    assert active[0]["technique"] == "recent"
    archive = (root / "knowledge.archive.jsonl").read_text()
    assert "old" in archive and "overflow" in archive


def test_workflow_expansion_drops_no_skill_lists():
    expanded = Orchestrator._expand_skills(["*"])
    assert {"sqli", "xss", "css-injection", "cryptographic-oracle"} <= set(expanded)
    assert "business-logic" in expanded
    web = Router("web_app").get_phase_skills("hunting")
    assert "sqli" in web and "css-injection" in web
    cloud = Router(workflow_path=str(ROOT / "workflows" / "cloud-pentest.yaml"))
    assert "aws-attack" in cloud.get_phase_skills("hunting")
    mobile = Router(workflow_path=str(ROOT / "workflows" / "mobile-pentest.yaml"))
    mobile_skills = mobile.get_phase_skills("hunting")
    assert "mobile-android" in mobile_skills and "idor" in mobile_skills
    run = Orchestrator(tempfile.mkdtemp()).create_run(ROOT / "workflows" / "mobile-pentest.yaml")
    hunting = [task["skill"] for task in run["tasks"] if task["phase"] == "hunting"]
    assert "mobile-ios" in hunting and "sqli" in hunting and "hunting" not in hunting


def test_concurrent_artifact_index():
    root = tempfile.mkdtemp()
    def capture(index):
        ArtifactStore(root).capture("R1", f"T{index}", "stdout.txt", f"complete-{index}")
    threads = [threading.Thread(target=capture, args=(index,)) for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    store = ArtifactStore(root)
    assert len(store.list()) == 12 and store.verify()["intact"]


def test_http_approval_consumed_after_attempt():
    class FakeResponse:
        status = 204
        headers = {}
        def read(self):
            return b"ok"
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    class FakeOpener:
        def open(self, request, timeout):
            return FakeResponse()

    root = authorized_root()
    url = "https://example.test/change"
    action = f"POST {url} {b'data'!r}"
    policy = PolicyEngine(root)
    digest = policy.grant(action, [url],
        (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())
    client = ProtectedHTTPClient(root)
    client.opener = FakeOpener()
    result = client.request("POST", url, body=b"data", dangerous=True, approved_digest=digest)
    assert result["status"] == 204 and not policy.valid_approval(digest)
    try:
        client.request("POST", url, body=b"data", dangerous=True, approved_digest=digest)
        raise AssertionError("HTTP approval was reusable")
    except PolicyDenied:
        pass


def test_bundle_contains_only_manifest_files():
    root = Path(tempfile.mkdtemp())
    (root / "report.md").write_text("report")
    (root / "vault.json").write_text("do-not-ship")
    (root / "vault.key").write_text("do-not-ship")
    (root / "link.txt").symlink_to(root / "report.md")
    output = Path(tempfile.mkdtemp()) / "delivery.tar.gz"
    result = bundle(str(root), str(output))
    assert result["manifest_verified"]
    with tarfile.open(output) as archive:
        names = archive.getnames()
    assert any(name.endswith("/report.md") for name in names)
    assert any(name.endswith("/manifest.json") for name in names)
    assert not any("vault" in name or "link.txt" in name for name in names)


def main():
    tests = [test_tool_registry_fallback_and_gap, test_wordlist_reproducibility,
             test_recon_dedup_scope_provenance_and_ranking,
             test_memory_retention_archives_before_pruning,
             test_workflow_expansion_drops_no_skill_lists, test_concurrent_artifact_index,
             test_http_approval_consumed_after_attempt, test_bundle_contains_only_manifest_files]
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
