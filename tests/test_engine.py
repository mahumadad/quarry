#!/usr/bin/env python3
"""Engine smoke tests — importable modules + core behaviors.

Run: python3 tests/test_engine.py
No external deps, no network. Each test uses a temp dir as engagement root.
"""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES = []


def check(name, fn):
    try:
        fn()
        print(f"  OK: {name}")
    except Exception as e:  # noqa: BLE001 — test runner reports anything
        FAILURES.append(f"{name}: {e}")
        print(f"  FAIL: {name}: {e}")


def test_oast():
    from engine.oast import OASTManager, Interaction
    d = tempfile.mkdtemp()
    o = OASTManager(d)
    tok = o.new_token("blind-ssrf", "ssrf", "https://{target}/hook", "url",
                      "x.oast.fun")
    assert tok.token in tok.payload_url
    # unmatched interaction is noise
    r = o.record_interaction(Interaction(token="deadbeef" * 2, protocol="http"))
    assert r["matched"] is False
    # matched interaction produces evidence
    r = o.record_interaction(Interaction(token=tok.token, protocol="http",
                                         remote_addr="203.0.113.9"))
    assert r["matched"] is True
    ev = o.evidence_record(tok.token)
    assert ev and ev["correlation"] == "unique-token"
    assert o.confirm(tok.token, "F-TEST0001")
    # persistence round-trip
    o2 = OASTManager(d)
    assert o2.evidence_record(tok.token) is not None


def test_sessions():
    from engine.sessions import SessionManager, Session
    d = tempfile.mkdtemp()
    s = SessionManager(d)
    assert not s.has_pair()
    s.register(Session(name="a", cookies={"s": "1"}))
    assert not s.has_pair()
    s.register(Session(name="b", headers={"Authorization": "Bearer 2"}))
    assert s.has_pair()
    flags = s.curl_flags("b")
    assert "Authorization" in flags
    assert s.update_material("a", cookies={"s": "refreshed"})
    assert SessionManager(d).get("a").cookies["s"] == "refreshed"


def test_knowledge():
    from engine.knowledge import KnowledgeBase, TechniqueRecord
    d = tempfile.mkdtemp()
    kb = KnowledgeBase(Path(d) / "kb.json")
    kb.record(TechniqueRecord(technique="decimal-ip", vuln_class="ssrf",
                              stack=["nginx"], outcome="worked"))
    kb.record(TechniqueRecord(technique="decimal-ip", vuln_class="ssrf",
                              stack=["nginx"], outcome="worked"))
    worked = kb.what_worked(stack=["nginx"], vuln_class="ssrf")
    assert len(worked) == 1 and worked[0].times_seen == 2
    assert not kb.what_failed(stack=["nginx"])


def test_custody():
    from engine.custody import CustodyLog
    d = tempfile.mkdtemp()
    c = CustodyLog(d)
    c.scope_confirmed({"targets": ["{target_domain}"]})
    c.operator_gate("exploit F-1", approved=True)
    c.export("sarif", "/tmp/x.sarif", 3)
    v = c.verify()
    assert v["intact"] and v["entries"] == 3
    # tamper detection: corrupt one line
    log = Path(d) / ".pentest-state" / "custody.jsonl"
    lines = log.read_text().splitlines()
    import json as _json
    rec = _json.loads(lines[1])
    rec["detail"]["approved"] = False
    lines[1] = _json.dumps(rec)
    log.write_text("\n".join(lines) + "\n")
    v2 = CustodyLog(d).verify()
    assert not v2["intact"]


def test_toolrunner():
    from engine.toolrunner import ToolRunner
    d = tempfile.mkdtemp()
    tr = ToolRunner(d)
    assert tr.is_available("python3")
    assert not tr.is_available("definitely-not-a-real-tool-xyz")
    # retry guard: identical command refused after 3 runs
    for _ in range(3):
        tr.run(["echo", "hi"])
    res = tr.run(["echo", "hi"])
    assert res.exit_code == 126 and "refused" in res.stderr


def test_exporters():
    from engine.findings import FindingsStore, Finding, FindingStatus, Evidence, EvidenceTag
    from engine.exporters import to_sarif, to_json, to_csv
    d = tempfile.mkdtemp()
    store = FindingsStore(d)
    # Follow the runtime path: findings are born 'detected' and advanced through
    # the evidence gate, not constructed pre-validated.
    f = Finding(title="IDOR en invoices", vuln_class="idor", severity="high",
                cvss_score=7.1, cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                target_asset="https://{target}/api/invoices",
                evidence_tag=EvidenceTag.DEMONSTRATED.value,
                steps_to_reproduce=["GET /api/invoices/42 as user B returns user A's invoice"])
    store.add(f)
    store.add_evidence(f.id, Evidence(type="request_response", content="GET /api/invoices/42 -> 200",
                                      tag=EvidenceTag.DEMONSTRATED.value))
    store.update_status(f.id, FindingStatus.CONFIRMED)
    store.update_status(f.id, FindingStatus.VALIDATED)
    sarif = to_sarif(store)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["properties"]["cvss_score"] == 7.1
    js = to_json(store)
    assert js["count"] == 1 and js["findings"][0]["vuln_class"] == "idor"
    assert "IDOR" in to_csv(store)
    # detected (not validated) findings stay out of exports
    store.add(Finding(title="lead", vuln_class="xss", status=FindingStatus.DETECTED.value))
    assert to_json(store)["count"] == 1


def test_timeguard():
    from engine.timeguard import TimeWindowGuard
    from datetime import datetime
    from zoneinfo import ZoneInfo
    d = tempfile.mkdtemp()
    g = TimeWindowGuard(d)
    ok, reason = g.is_allowed()
    assert ok and "no window configured" in reason  # fail-open sin config
    g.configure(
        windows=[{"days": ["mon"], "start": "09:00", "end": "18:00"}],
        timezone="UTC",
        expires_at="2027-01-01T00:00:00+00:00",
    )
    monday_noon = datetime(2026, 10, 26, 12, 0, tzinfo=ZoneInfo("UTC"))  # lunes
    monday_3am = datetime(2026, 10, 26, 3, 0, tzinfo=ZoneInfo("UTC"))
    tuesday_noon = datetime(2026, 10, 27, 12, 0, tzinfo=ZoneInfo("UTC"))
    assert g.is_allowed(monday_noon)[0]
    assert not g.is_allowed(monday_3am)[0]
    assert not g.is_allowed(tuesday_noon)[0]
    ok, reason = g.override("emergency")
    assert not ok  # allow_override=false por defecto
    # expiración
    after = datetime(2027, 6, 1, 12, 0, tzinfo=ZoneInfo("UTC"))
    allowed, reason = g.is_allowed(after)
    assert not allowed and "expired" in reason


def test_deliver():
    from engine.deliver import build_manifest, verify_manifest, bundle
    d = Path(tempfile.mkdtemp())
    (d / "report.md").write_text("# Reporte\n")
    (d / "evidence.txt").write_text("request/response raw\n")
    m = build_manifest(str(d))
    assert m["file_count"] == 2
    v = verify_manifest(str(d))
    assert v["intact"]
    # alteración detectada
    (d / "evidence.txt").write_text("tampered\n")
    v2 = verify_manifest(str(d))
    assert not v2["intact"] and "evidence.txt" in v2["altered"]
    # bundle
    (d / "evidence.txt").write_text("request/response raw\n")
    out = Path(tempfile.mkdtemp()) / "bundle.tar.gz"
    r = bundle(str(d), str(out))
    assert Path(r["bundle"]).exists() and r["bundle_sha256"]


def main() -> int:
    print("=" * 60)
    print("ENGINE SMOKE TESTS")
    print("=" * 60)
    check("oast", test_oast)
    check("sessions", test_sessions)
    check("knowledge", test_knowledge)
    check("custody", test_custody)
    check("toolrunner", test_toolrunner)
    check("exporters", test_exporters)
    check("timeguard", test_timeguard)
    check("deliver", test_deliver)
    print(f"\nRESULTS: {len(FAILURES)} failures")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
