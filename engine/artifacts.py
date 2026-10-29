"""Immutable raw-artifact store with provenance and safe display views."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from .redaction import redact
    from .storage import atomic_write_bytes, atomic_write_json, engagement_lock, read_json
except ImportError:
    from redaction import redact
    from storage import atomic_write_bytes, atomic_write_json, engagement_lock, read_json


@dataclass
class Artifact:
    artifact_id: str
    kind: str
    path: str
    sha256: str
    size: int
    content_type: str = "application/octet-stream"
    complete: bool = True
    truncated: bool = False
    redacted_path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    captured_at: str = ""

    def __post_init__(self):
        if not self.captured_at:
            self.captured_at = datetime.now(timezone.utc).isoformat()


class ArtifactStore:
    def __init__(self, audit_dir: str | Path):
        self.audit_dir = Path(audit_dir)
        self.root = self.audit_dir / "raw"
        self.index_file = self.audit_dir / ".pentest-state" / "artifacts.json"

    def capture(self, run_id: str, task_id: str, kind: str, content: bytes | str,
                content_type: str = "text/plain; charset=utf-8", complete: bool = True,
                truncated: bool = False, metadata: dict | None = None) -> Artifact:
        raw = content.encode("utf-8") if isinstance(content, str) else content
        safe_run = self._safe(run_id)
        safe_task = self._safe(task_id)
        safe_kind = self._safe(kind)
        relative = Path(safe_run) / safe_task / safe_kind
        destination = self.root / relative
        record = Artifact(
            artifact_id=hashlib.sha256(f"{run_id}:{task_id}:{kind}".encode()).hexdigest()[:20],
            kind=kind, path=str(relative), sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw), content_type=content_type, complete=complete,
            truncated=truncated, metadata=redact(metadata or {}),
        )
        with engagement_lock(self.audit_dir):
            atomic_write_bytes(destination, raw)
            view = redact(raw.decode("utf-8", errors="replace")).encode("utf-8")
            redacted_destination = destination.with_name(destination.name + ".redacted.txt")
            atomic_write_bytes(redacted_destination, view)
            record.redacted_path = str(redacted_destination.relative_to(self.audit_dir))
            records = self.list()
            records = [r for r in records if r["artifact_id"] != record.artifact_id]
            records.append(asdict(record))
            atomic_write_json(self.index_file, {"artifacts": records,
                "updated_at": datetime.now(timezone.utc).isoformat()})
        return record

    def list(self) -> list[dict]:
        if not self.index_file.exists():
            return []
        return read_json(self.index_file).get("artifacts", [])

    def verify(self) -> dict:
        missing, altered = [], []
        for record in self.list():
            path = self.root / record["path"]
            if not path.exists():
                missing.append(record["path"])
            elif hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                altered.append(record["path"])
        return {"intact": not missing and not altered, "missing": missing, "altered": altered}

    @staticmethod
    def _safe(value: str) -> str:
        cleaned = "".join(c if c.isalnum() or c in "-_" else "-" for c in value).strip("-")
        if not cleaned:
            raise ValueError("Artifact path component cannot be empty")
        return cleaned
