"""Normalized recon handoffs with scope, deduplication and provenance.

Each source emits observations; this module does not scan. It canonicalizes
assets between recon stages, retains out-of-scope discoveries as unauthorized
candidates, and ranks in-scope surface using explicit, reproducible signals.
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from .artifacts import ArtifactStore
    from .policy import PolicyEngine
    from .storage import atomic_write_json, engagement_lock, read_json
except ImportError:
    from artifacts import ArtifactStore
    from policy import PolicyEngine
    from storage import atomic_write_json, engagement_lock, read_json

TARGET_KINDS = {"host", "subdomain", "asset", "url", "endpoint", "http_service"}
RANK_SIGNALS = {
    "sensitive_function": (10, "sensitive function or crown-jewel workflow"),
    "admin": (8, "administrative surface"),
    "legacy": (7, "legacy version or route"),
    "forgotten": (7, "forgotten or historical-only surface"),
    "upload": (6, "file upload or parser"),
    "import_export": (6, "import/export workflow"),
    "webhook": (5, "webhook or callback"),
    "integration": (5, "third-party integration"),
    "multi_tenant": (5, "multi-tenant authorization boundary"),
    "new": (4, "new since previous snapshot"),
    "paid_plan": (3, "paid-plan-only surface"),
    "free_plan": (2, "free/paid authorization delta"),
    "api": (2, "API surface"),
}


@dataclass
class Observation:
    kind: str
    value: str
    source: str
    stage: str
    observed_at: str = ""
    complete: bool = True
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.observed_at:
            self.observed_at = datetime.now(timezone.utc).isoformat()


def canonicalize(kind: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Recon observation cannot be empty")
    if kind in {"host", "subdomain", "asset"}:
        parsed = urlsplit(value if "://" in value else f"//{value}")
        host = (parsed.hostname or value).lower().rstrip(".")
        try:
            return ipaddress.ip_address(host).compressed
        except ValueError:
            return host.encode("idna").decode("ascii")
    if kind in {"url", "endpoint", "http_service"}:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"Not a canonical HTTP(S) observation: {value}")
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port
        netloc = host if port is None or port == (443 if parsed.scheme.lower() == "https" else 80) else f"{host}:{port}"
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", query, ""))
    return value.lower() if kind in {"technology", "waf"} else value


class ReconPipeline:
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.state_file = self.audit_dir / ".pentest-state" / "recon-inventory.json"
        self.scope = PolicyEngine(self.audit_dir).load_scope()

    def ingest(self, observations: list[Observation]) -> dict:
        with engagement_lock(self.audit_dir):
            data = read_json(self.state_file, {"schema_version": 1, "records": []})
            records = {(item["kind"], item["value"]): item for item in data.get("records", [])}
            stats = {"received": len(observations), "new": 0, "merged": 0, "out_of_scope": 0}
            for observation in observations:
                if not observation.source.strip() or not observation.stage.strip():
                    raise ValueError("Every observation requires source and stage provenance")
                value = canonicalize(observation.kind, observation.value)
                in_scope = self.scope.is_in_scope(value) if observation.kind in TARGET_KINDS else True
                status = "in_scope" if in_scope else "out_of_scope_pending_authorization"
                stats["out_of_scope"] += int(not in_scope)
                key = (observation.kind, value)
                provenance = {
                    "source": observation.source,
                    "stage": observation.stage,
                    "observed_at": observation.observed_at,
                    "complete": observation.complete,
                    "metadata": observation.metadata,
                }
                if key not in records:
                    stats["new"] += 1
                    records[key] = {
                        "kind": observation.kind,
                        "value": value,
                        "status": status,
                        "first_seen": observation.observed_at,
                        "last_seen": observation.observed_at,
                        "provenance": [provenance],
                        "metadata": dict(observation.metadata),
                    }
                else:
                    stats["merged"] += 1
                    record = records[key]
                    record["last_seen"] = max(record["last_seen"], observation.observed_at)
                    if provenance not in record["provenance"]:
                        record["provenance"].append(provenance)
                    record["metadata"].update(observation.metadata)
                    # A previously external candidate still requires an explicit scope change;
                    # the new Scope loaded for this run is the sole authority for its status.
                    record["status"] = status
            ordered = sorted(records.values(), key=lambda item: (item["kind"], item["value"]))
            result = {"schema_version": 1, "records": ordered,
                      "updated_at": datetime.now(timezone.utc).isoformat()}
            atomic_write_json(self.state_file, result)
        return {"stats": stats, "ranked_assets": self.rank(ordered)}

    def rank(self, records: list[dict] | None = None) -> list[dict]:
        if records is None:
            records = read_json(self.state_file, {"records": []}).get("records", [])
        ranked = []
        for record in records:
            if record.get("status") != "in_scope":
                continue
            score, reasons = 0, []
            for signal, (weight, reason) in RANK_SIGNALS.items():
                if record.get("metadata", {}).get(signal) is True:
                    score += weight
                    reasons.append(reason)
            ranked.append({"kind": record["kind"], "value": record["value"],
                           "priority_score": score, "priority_reasons": reasons,
                           "source_count": len(record.get("provenance", []))})
        return sorted(ranked, key=lambda item: (-item["priority_score"], item["kind"], item["value"]))

    def save_artifact(self, run_id: str, task_id: str = "recon-inventory"):
        data = read_json(self.state_file, {"records": []})
        return ArtifactStore(self.audit_dir).capture(run_id, task_id, "recon-inventory.json",
            __import__("json").dumps(data, indent=2), content_type="application/json",
            metadata={"record_count": len(data.get("records", []))})
