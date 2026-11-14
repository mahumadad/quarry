"""Differential retest (#6): auto-fire prior PoCs through scope + approval gate.

These tests exercise the REAL scope and approval policy (via ProtectedHTTPClient);
only the socket is faked, so out-of-scope/no-approval blocking is genuinely tested.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))

from http_client import ProtectedHTTPClient  # noqa: E402
from retest import RetestPoC, grant_retest, run_retest  # noqa: E402


class _FakeResp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


class _FakeOpener:
    """Stands in for the urllib opener: records calls, returns a canned response."""
    def __init__(self, status=200, headers=None, body=b""):
        self.calls = []
        self.status, self.headers, self.body = status, headers or {}, body

    def open(self, request, timeout=None):
        self.calls.append(request.full_url)
        return _FakeResp(self.status, self.headers, self.body)


def _client(audit_dir, status=200, body=b""):
    c = ProtectedHTTPClient(audit_dir)
    c.opener = _FakeOpener(status=status, body=body)
    return c


@pytest.fixture()
def engagement(tmp_path):
    state = tmp_path / ".pentest-state"
    state.mkdir()
    state.joinpath("scope.json").write_text(json.dumps({
        "authorization": "Authorized by operator for retest",
        "in_scope": [{"pattern": "app.test", "type": "domain", "notes": ""}],
        "out_of_scope": [],
        "rules": [],
    }))
    state.joinpath("window.json").write_text(json.dumps({
        "timezone": "UTC",
        "windows": [{"days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                     "start": "00:00", "end": "23:59"}],
        "expires_at": "2099-12-31T23:59:59+00:00",
        "allow_override": False,
    }))
    return tmp_path


def _future():
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def _poc(**kw):
    kw.setdefault("method", "GET")
    kw.setdefault("url", "https://app.test/leak")
    kw.setdefault("match", [{"type": "body_contains", "value": "SECRET"}])
    return RetestPoC(**kw)


def test_still_vulnerable_is_not_fixed(engagement):
    poc = _poc(finding_id="F1")
    grant_retest(engagement, [poc], _future())
    client = _client(engagement, status=200, body=b"user data SECRET token")
    res = run_retest(engagement, [poc], run_id="r1", client=client)
    assert res["F1"]["status"] == "not_fixed"
    assert client.opener.calls  # it was actually fired


def test_fixed_when_signature_gone(engagement):
    poc = _poc(finding_id="F2")
    grant_retest(engagement, [poc], _future())
    client = _client(engagement, status=403, body=b"forbidden")
    res = run_retest(engagement, [poc], run_id="r1", client=client)
    assert res["F2"]["status"] == "fixed"


def test_out_of_scope_not_fired(engagement):
    poc = _poc(finding_id="F3", url="https://evil.com/leak")
    grant_retest(engagement, [poc], _future())  # grant should skip it
    client = _client(engagement, status=200, body=b"SECRET")
    res = run_retest(engagement, [poc], run_id="r1", client=client)
    assert res["F3"]["status"] == "inconclusive"
    assert "scope" in res["F3"]["reason"].lower()
    assert client.opener.calls == []  # never left the process


def test_no_approval_not_fired(engagement):
    poc = _poc(finding_id="F4")  # in scope but NOT granted
    client = _client(engagement, status=200, body=b"SECRET")
    res = run_retest(engagement, [poc], run_id="r1", client=client)
    assert res["F4"]["status"] == "inconclusive"
    assert "approv" in res["F4"]["reason"].lower()
    assert client.opener.calls == []


def test_destructive_never_autofired(engagement):
    poc = _poc(finding_id="F5", destructive=True)
    grant_retest(engagement, [poc], _future())
    client = _client(engagement, status=200, body=b"SECRET")
    res = run_retest(engagement, [poc], run_id="r1", client=client)
    assert res["F5"]["status"] == "inconclusive"
    assert "destructive" in res["F5"]["reason"].lower()
    assert client.opener.calls == []


def test_regression_detected_across_runs(engagement):
    poc = _poc(finding_id="F6")
    grant_retest(engagement, [poc], _future())
    run_retest(engagement, [poc], run_id="r1",
               client=_client(engagement, status=403, body=b"forbidden"))  # fixed
    grant_retest(engagement, [poc], _future())  # re-grant: approval is single-use
    res = run_retest(engagement, [poc], run_id="r2",
                     client=_client(engagement, status=200, body=b"SECRET"))  # back
    assert res["F6"]["status"] == "regressed"


def test_results_persisted(engagement):
    poc = _poc(finding_id="F7")
    grant_retest(engagement, [poc], _future())
    run_retest(engagement, [poc], run_id="r1",
               client=_client(engagement, status=200, body=b"SECRET"))
    log = engagement / ".pentest-state" / "retest.jsonl"
    assert log.exists()
    records = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    assert any(r["finding_id"] == "F7" and r["status"] == "not_fixed" for r in records)


def test_grant_reports_skips(engagement):
    pocs = [_poc(finding_id="A"), _poc(finding_id="B", url="https://evil.com/x"),
            _poc(finding_id="C", destructive=True)]
    result = grant_retest(engagement, pocs, _future())
    assert "A" in result["granted"]
    skipped_ids = {sid for sid, _ in result["skipped"]}
    assert skipped_ids == {"B", "C"}
