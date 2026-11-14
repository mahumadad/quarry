"""Differential retest: auto-fire prior findings' PoCs and classify regressions.

Re-runs a stored, replayable HTTP PoC for each prior finding and labels it with the
retest vocabulary (``fixed`` / ``not_fixed`` / ``regressed`` / ``inconclusive``). Every
fire goes through ``ProtectedHTTPClient`` so it is validated against the CURRENT
engagement scope and requires a single-use operator approval (the gate). Two safety
invariants hold regardless of approval:

* **Scope:** an out-of-scope PoC is never fired (the policy engine blocks it).
* **Destructive PoCs are never auto-fired** — they are reported ``inconclusive`` with a
  reason so the operator retests them by hand. ``PARTIAL`` (original fails, a variant
  works) is likewise a human judgment and never an auto-fire outcome.

Results are appended, per finding, to ``.pentest-state/retest.jsonl`` so a later run can
tell that a previously ``fixed`` finding has ``regressed``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .http_client import ProtectedHTTPClient
    from .policy import (PolicyDenied, PolicyEngine, approval_digest,
                         canonical_url_target)
    from .storage import append_jsonl, engagement_lock
except ImportError:
    from http_client import ProtectedHTTPClient
    from policy import (PolicyDenied, PolicyEngine, approval_digest,
                        canonical_url_target)
    from storage import append_jsonl, engagement_lock


@dataclass
class RetestPoC:
    """A replayable HTTP proof for a prior finding.

    ``match`` is a list of conditions; the PoC is judged *still vulnerable* when ALL of
    them hold against the re-test response. Condition types:
      - ``status_eq``:       {"type": "status_eq", "value": 200}
      - ``status_in``:       {"type": "status_in", "value": [200, 201]}
      - ``body_contains``:   {"type": "body_contains", "value": "SECRET"}
      - ``body_absent``:     {"type": "body_absent", "value": "Access denied"}
      - ``header_contains``: {"type": "header_contains", "value": ["X-Debug", "on"]}
    """
    finding_id: str
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    match: list[dict] = field(default_factory=list)
    destructive: bool = False


def _action_target(poc: RetestPoC) -> tuple[str, str, bytes | None]:
    """The (action string, canonical target, body bytes) used for the approval digest.

    Must mirror exactly what ProtectedHTTPClient.request builds, or the single-use
    approval will not match and the fire will be denied.
    """
    body_bytes = poc.body.encode() if poc.body is not None else None
    target = canonical_url_target(poc.url)
    action = f"{poc.method} {poc.url} {body_bytes!r}"
    return action, target, body_bytes


def grant_retest(audit_dir: str | Path, pocs: list[RetestPoC], expires_at: str,
                 actor: str = "operator") -> dict[str, Any]:
    """The operator gate: grant single-use approvals for every auto-firable PoC.

    Skips destructive PoCs and out-of-scope PoCs (they are never auto-fired). Returns
    the finding ids granted and the ones skipped with a reason.
    """
    engine = PolicyEngine(audit_dir)
    scope = engine.load_scope()
    granted: list[str] = []
    skipped: list[tuple[str, str]] = []
    for poc in pocs:
        if poc.destructive:
            skipped.append((poc.finding_id, "destructive PoC: manual retest only"))
            continue
        try:
            action, target, _ = _action_target(poc)
        except PolicyDenied as exc:
            skipped.append((poc.finding_id, f"non-canonical URL: {exc}"))
            continue
        if not scope.is_in_scope(target):
            skipped.append((poc.finding_id, "out of scope in current engagement"))
            continue
        engine.grant(action, [target], expires_at, actor=actor)
        granted.append(poc.finding_id)
    return {"granted": granted, "skipped": skipped}


def _still_vulnerable(result: dict, conditions: list[dict]) -> bool:
    body = result.get("body", b"")
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    headers = result.get("headers", {})
    status = result.get("status", 0)
    for cond in conditions:
        ctype, value = cond.get("type"), cond.get("value")
        if ctype == "status_eq" and status != value:
            return False
        elif ctype == "status_in" and status not in value:
            return False
        elif ctype == "body_contains" and value not in body:
            return False
        elif ctype == "body_absent" and value in body:
            return False
        elif ctype == "header_contains":
            name, substr = value
            if substr not in headers.get(name, ""):
                return False
    return True


def _last_status(audit_dir: str | Path, finding_id: str) -> str | None:
    log = Path(audit_dir) / ".pentest-state" / "retest.jsonl"
    if not log.exists():
        return None
    last = None
    for line in log.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("finding_id") == finding_id:
            last = rec.get("status")
    return last


def _retest_one(audit_dir: str | Path, poc: RetestPoC, run_id: str,
                client: ProtectedHTTPClient) -> dict[str, Any]:
    if poc.destructive:
        return {"status": "inconclusive", "reason": "destructive PoC: manual retest only",
                "fired": False, "response_status": None}
    if not poc.match:
        return {"status": "inconclusive", "reason": "PoC has no match conditions",
                "fired": False, "response_status": None}
    try:
        action, target, body_bytes = _action_target(poc)
    except PolicyDenied as exc:
        return {"status": "inconclusive", "reason": f"non-canonical URL: {exc}",
                "fired": False, "response_status": None}
    digest = approval_digest(action, target)
    try:
        result = client.request(poc.method, poc.url, headers=poc.headers, body=body_bytes,
                                dangerous=True, approved_digest=digest,
                                run_id=run_id, task_id=poc.finding_id)
    except PolicyDenied as exc:
        reason = str(exc)
        # Distinguish scope from the approval gate for the operator's benefit.
        tag = "out of scope" if "OUT OF SCOPE" in reason or "not configured" in reason else reason
        return {"status": "inconclusive", "reason": tag, "fired": False,
                "response_status": None}
    if result.get("error"):
        return {"status": "inconclusive", "reason": result["error"], "fired": True,
                "response_status": result.get("status"),
                "response_artifact": result.get("response_artifact")}
    still = _still_vulnerable(result, poc.match)
    status = "not_fixed" if still else "fixed"
    if status == "not_fixed" and _last_status(audit_dir, poc.finding_id) == "fixed":
        status = "regressed"
    return {"status": status, "reason": "", "fired": True,
            "response_status": result.get("status"),
            "response_artifact": result.get("response_artifact")}


def run_retest(audit_dir: str | Path, pocs: list[RetestPoC], run_id: str = "retest",
               client: ProtectedHTTPClient | None = None) -> dict[str, dict]:
    """Auto-fire each PoC through the scope/approval gate and classify the outcome.

    Returns ``{finding_id: result}`` and appends one record per finding to
    ``.pentest-state/retest.jsonl``.
    """
    client = client or ProtectedHTTPClient(audit_dir)
    log = Path(audit_dir) / ".pentest-state" / "retest.jsonl"
    results: dict[str, dict] = {}
    for poc in pocs:
        res = _retest_one(audit_dir, poc, run_id, client)
        results[poc.finding_id] = res
        record = {"finding_id": poc.finding_id, "run_id": run_id,
                  "at": datetime.now(timezone.utc).isoformat(),
                  "status": res["status"], "reason": res["reason"],
                  "fired": res["fired"], "response_status": res.get("response_status")}
        with engagement_lock(audit_dir):
            append_jsonl(log, record)
    return results
