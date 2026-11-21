"""3-Gate finding confirmation protocol.

Inspired by CyberStrike's verification approach: every finding must pass
three gates before being promoted to Demonstrated status.

Gate 1 — Baseline: send a normal, benign request and record the response.
Gate 2 — Attack:   send the exploit request and record the response.
Gate 3 — Diff:     compare baseline vs attack; meaningful difference = confirmed.

If the diff is only noise (timestamps, CSRF tokens, request IDs), the
finding is downgraded to Inferred or marked as likely false positive.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any


NOISE_PATTERNS = [
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    re.compile(r"\b\d{10,13}\b"),
    re.compile(r'"(csrf|nonce|token|_token|requestId|request_id|trace_id)":\s*"[^"]*"', re.I),
    re.compile(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+[\d:]+\s+\w+"),
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
    re.compile(r"Set-Cookie:\s*[^\r\n]+", re.I),
]

SIGNIFICANT_INDICATORS = [
    "syntax error",
    "sql",
    "mysql",
    "postgresql",
    "sqlite",
    "oracle",
    "stack trace",
    "traceback",
    "exception",
    "error in",
    "<script",
    "alert(",
    "onerror",
    "onload",
    "document.cookie",
    "passwd",
    "root:",
    "/etc/",
    "internal server error",
    "debug",
]


@dataclass
class GateResult:
    gate: str
    status: int
    body_hash: str
    body_length: int
    headers: dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    error: str = ""


@dataclass
class ThreeGateVerdict:
    finding_id: str
    verdict: str  # "anomaly_detected" | "likely_fp" | "inconclusive"
    confidence: float  # 0.0 - 1.0
    baseline: GateResult | None = None
    attack: GateResult | None = None
    diff_ratio: float = 0.0
    significant_diffs: list[str] = field(default_factory=list)
    noise_stripped: bool = False
    reason: str = ""
    verified_at: str = ""

    def __post_init__(self):
        if not self.verified_at:
            self.verified_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def _strip_noise(text: str) -> str:
    result = text
    for pat in NOISE_PATTERNS:
        result = pat.sub("[NOISE]", result)
    return result


def _body_hash(body: bytes | str) -> str:
    if isinstance(body, str):
        body = body.encode("utf-8", errors="replace")
    return hashlib.sha256(body).hexdigest()[:16]


def _extract_significant(baseline_body: str, attack_body: str) -> list[str]:
    diffs = []
    attack_lower = attack_body.lower()
    baseline_lower = baseline_body.lower()
    for indicator in SIGNIFICANT_INDICATORS:
        if indicator in attack_lower and indicator not in baseline_lower:
            diffs.append(f"Indicator '{indicator}' appeared in attack response")
    return diffs


def run_gate(method: str, url: str, headers: dict[str, str] | None,
             body: bytes | None, http_client: Any,
             gate_name: str) -> GateResult:
    try:
        resp = http_client.request(
            method, url, headers=headers, body=body, timeout=30,
            run_id="three_gate", task_id=f"gate_{gate_name}",
        )
        resp_body = resp.get("body", b"")
        if isinstance(resp_body, bytes):
            resp_body_str = resp_body.decode("utf-8", errors="replace")
        else:
            resp_body_str = str(resp_body)
        return GateResult(
            gate=gate_name,
            status=resp.get("status", 0),
            body_hash=_body_hash(resp_body),
            body_length=len(resp_body),
            headers=resp.get("headers", {}),
            body_snippet=resp_body_str[:500],
            error=resp.get("error", ""),
        )
    except Exception as exc:
        return GateResult(
            gate=gate_name, status=0, body_hash="", body_length=0,
            error=f"{type(exc).__name__}: {exc}",
        )


def verify_finding(
    finding_id: str,
    baseline_url: str,
    baseline_method: str = "GET",
    baseline_headers: dict[str, str] | None = None,
    baseline_body: bytes | None = None,
    attack_url: str = "",
    attack_method: str = "",
    attack_headers: dict[str, str] | None = None,
    attack_body: bytes | None = None,
    http_client: Any = None,
) -> ThreeGateVerdict:
    if http_client is None:
        raise ValueError("http_client is required")

    attack_url = attack_url or baseline_url
    attack_method = attack_method or baseline_method

    gate1 = run_gate(baseline_method, baseline_url, baseline_headers,
                     baseline_body, http_client, "baseline")
    if gate1.error:
        return ThreeGateVerdict(
            finding_id=finding_id, verdict="inconclusive", confidence=0.0,
            baseline=gate1, reason=f"Baseline failed: {gate1.error}",
        )

    gate2 = run_gate(attack_method, attack_url, attack_headers,
                     attack_body, http_client, "attack")
    if gate2.error:
        return ThreeGateVerdict(
            finding_id=finding_id, verdict="inconclusive", confidence=0.0,
            baseline=gate1, attack=gate2,
            reason=f"Attack failed: {gate2.error}",
        )

    status_diff = gate1.status != gate2.status

    baseline_clean = _strip_noise(gate1.body_snippet)
    attack_clean = _strip_noise(gate2.body_snippet)
    noise_stripped = baseline_clean != gate1.body_snippet or attack_clean != gate2.body_snippet

    ratio = SequenceMatcher(None, baseline_clean, attack_clean).ratio()
    diff_ratio = 1.0 - ratio

    significant = _extract_significant(gate1.body_snippet, gate2.body_snippet)

    if significant:
        verdict = "anomaly_detected"
        confidence = min(0.6 + 0.1 * len(significant), 0.99)
        reason = f"{len(significant)} significant indicator(s) in attack response"
    elif status_diff and diff_ratio > 0.05:
        verdict = "anomaly_detected"
        confidence = 0.7
        reason = f"Status changed ({gate1.status}→{gate2.status}) with {diff_ratio:.0%} body diff"
    elif diff_ratio > 0.3:
        verdict = "anomaly_detected"
        confidence = 0.6
        reason = f"Significant body diff ({diff_ratio:.0%}) after noise stripping"
    elif diff_ratio > 0.1 or status_diff:
        verdict = "inconclusive"
        confidence = 0.4
        reason = (
            f"Minor diff ({diff_ratio:.0%})"
            + (f", status changed ({gate1.status}→{gate2.status})" if status_diff else "")
        )
    else:
        verdict = "likely_fp"
        confidence = 0.8
        reason = f"No meaningful diff ({diff_ratio:.0%}) — response essentially identical"

    return ThreeGateVerdict(
        finding_id=finding_id,
        verdict=verdict,
        confidence=confidence,
        baseline=gate1,
        attack=gate2,
        diff_ratio=diff_ratio,
        significant_diffs=significant,
        noise_stripped=noise_stripped,
        reason=reason,
    )


def _evidence_content(verdict: ThreeGateVerdict) -> str:
    """Human + machine readable record of the baseline/attack round-trip."""
    b, a = verdict.baseline, verdict.attack
    return json.dumps({
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "reason": verdict.reason,
        "diff_ratio": round(verdict.diff_ratio, 4),
        "significant_diffs": verdict.significant_diffs,
        "baseline": {"status": b.status if b else None,
                     "body_hash": b.body_hash if b else "",
                     "snippet": b.body_snippet if b else ""},
        "attack": {"status": a.status if a else None,
                   "body_hash": a.body_hash if a else "",
                   "snippet": a.body_snippet if a else ""},
        "verified_at": verdict.verified_at,
    }, indent=2)


def verify_and_record(
    audit_dir: str,
    finding_id: str,
    baseline_url: str,
    baseline_method: str = "GET",
    baseline_headers: dict[str, str] | None = None,
    baseline_body: bytes | None = None,
    attack_url: str = "",
    attack_method: str = "",
    attack_headers: dict[str, str] | None = None,
    attack_body: bytes | None = None,
    http_client: Any = None,
    store: Any = None,
) -> ThreeGateVerdict:
    """Run the 3-gate protocol and persist the verdict to the finding.

    Only a ``confirmed`` verdict promotes the finding: evidence_tag becomes
    ``demonstrated`` and the status advances DETECTED→CONFIRMED. An
    ``inconclusive`` or ``likely_fp`` verdict is recorded as evidence (so the
    operator sees the finding WAS tested) but never silently promotes it —
    that is the whole point of the gate and of the anti-fabrication rule.
    """
    try:
        from .http_client import ProtectedHTTPClient
        from .findings import (Evidence, EvidenceTag, FindingsStore,
                               FindingStatus)
    except ImportError:  # top-level script mode
        from http_client import ProtectedHTTPClient
        from findings import (Evidence, EvidenceTag, FindingsStore,
                              FindingStatus)

    client = http_client or ProtectedHTTPClient(audit_dir)
    store = store or FindingsStore(audit_dir)

    verdict = verify_finding(
        finding_id=finding_id,
        baseline_url=baseline_url, baseline_method=baseline_method,
        baseline_headers=baseline_headers, baseline_body=baseline_body,
        attack_url=attack_url, attack_method=attack_method,
        attack_headers=attack_headers, attack_body=attack_body,
        http_client=client,
    )

    if store.get(finding_id) is None:
        return verdict  # nothing to persist onto; caller owns the finding

    anomaly = verdict.verdict == "anomaly_detected"
    tag = EvidenceTag.DEMONSTRATED if anomaly else EvidenceTag.UNPROVEN
    store.add_evidence(finding_id, Evidence(
        type="request_response",
        content=_evidence_content(verdict),
        tool="three_gate" if anomaly else "three_gate:{}".format(verdict.verdict),
        tag=tag.value,
    ))
    if anomaly:
        store.set_evidence_tag(finding_id, EvidenceTag.DEMONSTRATED,
                               reason="three_gate: {}".format(verdict.reason))
        # Advance only from DETECTED; a no-op if already further along.
        if store.get(finding_id).status == FindingStatus.DETECTED.value:
            store.update_status(finding_id, FindingStatus.CONFIRMED,
                                reason="three_gate confirmed")
    return verdict


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="engine.three_gate",
        description="Run the 3-gate verification protocol for a finding.")
    ap.add_argument("--audit-dir", default=".")
    ap.add_argument("--spec", help="JSON file with finding_id/baseline_url/"
                    "attack_url (+ optional method/headers/body fields)")
    ap.add_argument("--finding-id")
    ap.add_argument("--baseline-url")
    ap.add_argument("--attack-url")
    ap.add_argument("--record", dest="record", action="store_true", default=True)
    ap.add_argument("--no-record", dest="record", action="store_false")
    args = ap.parse_args()

    spec: dict[str, Any] = {}
    if args.spec:
        import pathlib
        spec = json.loads(pathlib.Path(args.spec).read_text())
    finding_id = args.finding_id or spec.get("finding_id", "")
    baseline_url = args.baseline_url or spec.get("baseline_url", "")
    attack_url = args.attack_url or spec.get("attack_url", "")
    if not finding_id or not baseline_url:
        ap.error("finding_id and baseline_url are required (flag or --spec)")

    common = dict(
        audit_dir=args.audit_dir, finding_id=finding_id,
        baseline_url=baseline_url,
        baseline_method=spec.get("baseline_method", "GET"),
        baseline_headers=spec.get("baseline_headers"),
        baseline_body=(spec.get("baseline_body") or "").encode() or None,
        attack_url=attack_url,
        attack_method=spec.get("attack_method", ""),
        attack_headers=spec.get("attack_headers"),
        attack_body=(spec.get("attack_body") or "").encode() or None,
    )
    if args.record:
        verdict = verify_and_record(**common)
    else:
        try:
            from .http_client import ProtectedHTTPClient
        except ImportError:
            from http_client import ProtectedHTTPClient
        verdict = verify_finding(http_client=ProtectedHTTPClient(args.audit_dir),
                                 **{k: v for k, v in common.items()
                                    if k != "audit_dir"})
    print(json.dumps(verdict.to_dict(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
