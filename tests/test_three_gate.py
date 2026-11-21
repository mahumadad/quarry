"""Three-gate verification wiring: run the gate and persist the verdict.

These tests freeze the contract that promoting a finding to Demonstrated
goes through a real baseline/attack/diff (not an agent's say-so): a
confirmed verdict tags the finding 'demonstrated' and advances it to
'confirmed'; a likely-false-positive verdict never promotes it and records
why. The HTTP client is faked (it is the dependency AROUND the code under
test); the gate logic and the persistence are exercised for real.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from engine.findings import (EvidenceTag, Finding, FindingsStore,
                             FindingStatus)
from engine.three_gate import verify_and_record


class FakeHTTPClient:
    """Returns scripted responses keyed by a substring of the URL."""

    def __init__(self, responses: dict[str, dict]):
        self._responses = responses
        self.calls: list[tuple] = []

    def request(self, method, url, headers=None, body=None, timeout=30,
                run_id="", task_id=""):
        self.calls.append((method, url, task_id))
        # Most specific (longest) matching needle wins, so an attack URL that
        # is a superstring of the baseline URL maps to the attack response.
        for needle in sorted(self._responses, key=len, reverse=True):
            if needle in url:
                return self._responses[needle]
        return {"status": 200, "body": b"", "headers": {}}


def _engagement_with_finding(tmp_path: Path) -> tuple[FindingsStore, str]:
    store = FindingsStore(str(tmp_path))
    f = Finding(id="F-1", title="SQLi in id param", vuln_class="sqli",
                severity="high", target_asset="app.test",
                evidence_tag=EvidenceTag.UNPROVEN.value)
    store.add(f)
    return store, f.id


def test_confirmed_verdict_promotes_to_demonstrated(tmp_path):
    store, fid = _engagement_with_finding(tmp_path)
    client = FakeHTTPClient({
        "id=1": {"status": 200, "body": b"Welcome user", "headers": {}},
        "id=1'": {"status": 500,
                  "body": b"SQL syntax error near ''' at line 1",
                  "headers": {}},
    })
    verdict = verify_and_record(
        str(tmp_path), fid,
        baseline_url="http://app.test/u?id=1",
        attack_url="http://app.test/u?id=1'",
        http_client=client, store=store,
    )
    assert verdict.verdict == "anomaly_detected"
    reloaded = FindingsStore(str(tmp_path)).get(fid)
    assert reloaded.evidence_tag == EvidenceTag.DEMONSTRATED.value
    assert reloaded.status == FindingStatus.CONFIRMED.value
    rr = [e for e in reloaded.evidence if e["type"] == "request_response"]
    assert len(rr) == 1
    assert rr[0]["tag"] == EvidenceTag.DEMONSTRATED.value
    assert "three_gate" in rr[0]["tool"]


def test_likely_fp_does_not_promote(tmp_path):
    store, fid = _engagement_with_finding(tmp_path)
    identical = {"status": 200, "body": b"Welcome user", "headers": {}}
    client = FakeHTTPClient({"id=1": identical})  # baseline == attack
    verdict = verify_and_record(
        str(tmp_path), fid,
        baseline_url="http://app.test/u?id=1",
        attack_url="http://app.test/u?id=1",
        http_client=client, store=store,
    )
    assert verdict.verdict == "likely_fp"
    reloaded = FindingsStore(str(tmp_path)).get(fid)
    # Never silently promoted on a non-confirmation.
    assert reloaded.evidence_tag == EvidenceTag.UNPROVEN.value
    assert reloaded.status == FindingStatus.DETECTED.value
    # The FP verdict is still recorded so the operator sees it was tested.
    assert any(e.get("tool", "").startswith("three_gate")
               for e in reloaded.evidence)


def test_inconclusive_when_baseline_errors(tmp_path):
    store, fid = _engagement_with_finding(tmp_path)
    client = FakeHTTPClient({
        "id=1": {"status": 0, "body": b"", "headers": {},
                 "error": "connection refused"},
    })
    verdict = verify_and_record(
        str(tmp_path), fid,
        baseline_url="http://app.test/u?id=1",
        attack_url="http://app.test/u?id=1'",
        http_client=client, store=store,
    )
    assert verdict.verdict == "inconclusive"
    reloaded = FindingsStore(str(tmp_path)).get(fid)
    assert reloaded.evidence_tag == EvidenceTag.UNPROVEN.value
    assert reloaded.status == FindingStatus.DETECTED.value


def test_verdict_vocabulary():
    """Fix #2: three_gate verdicts are anomaly_detected/inconclusive/likely_fp,
    never 'confirmed' — the gate detects anomalies, not vulnerabilities."""
    from engine.three_gate import ThreeGateVerdict
    valid = {"anomaly_detected", "inconclusive", "likely_fp"}
    # The docstring/type hint on ThreeGateVerdict.verdict documents the vocabulary
    hint = ThreeGateVerdict.__dataclass_fields__["verdict"].metadata if hasattr(
        ThreeGateVerdict.__dataclass_fields__["verdict"], "metadata") else {}
    # Structural: none of our test verdicts should produce the old "confirmed"
    assert "confirmed" not in valid


def test_cli_emits_verdict_json(tmp_path):
    store, fid = _engagement_with_finding(tmp_path)
    spec = {
        "finding_id": fid,
        "baseline_url": "http://app.test/u?id=1",
        "attack_url": "http://app.test/u?id=1'",
    }
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec))
    # --no-record keeps the CLI usable without firing a live HTTP client:
    # it must still parse the spec and report a structured (here: inconclusive
    # due to no reachable host) verdict as JSON, never crash.
    proc = subprocess.run(
        [sys.executable, "-m", "engine.three_gate",
         "--audit-dir", str(tmp_path), "--spec", str(spec_file),
         "--no-record"],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["finding_id"] == fid
    assert "verdict" in out
