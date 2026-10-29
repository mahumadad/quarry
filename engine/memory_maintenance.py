"""Explicit, non-destructive retention for the cross-engagement knowledge base."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from .storage import append_jsonl, atomic_write_json, read_json
except ImportError:
    from storage import append_jsonl, atomic_write_json, read_json


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def maintain_knowledge(path: str | Path, max_records: int = 5000,
                       max_age_days: int = 365, now: datetime | None = None) -> dict:
    """Archive expired/overflow records before removing them from active memory.

    Nothing is discarded silently: removed records go to a sibling JSONL archive.
    Retention is deterministic (recent, frequently observed records stay active).
    """
    if max_records < 1 or max_age_days < 1:
        raise ValueError("Retention limits must be positive")
    kb_file = Path(path)
    data = read_json(kb_file, {"records": []})
    records = data.get("records", [])
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    active, expired = [], []
    for record in records:
        try:
            seen = _timestamp(record.get("last_seen") or record.get("first_seen"))
        except (TypeError, ValueError):
            # Malformed dates are retained for review rather than silently deleted.
            active.append(record)
        else:
            (active if seen >= cutoff else expired).append(record)
    active.sort(key=lambda item: (item.get("last_seen", ""),
                                  int(item.get("times_seen", 1)),
                                  item.get("technique", "")), reverse=True)
    overflow = active[max_records:]
    kept = active[:max_records]
    removed = expired + overflow
    pruned_at = now.isoformat()
    if removed:
        append_jsonl(kb_file.with_suffix(".archive.jsonl"), {
            "event": "knowledge_retention", "pruned_at": pruned_at, "records": removed})
    atomic_write_json(kb_file, {**data, "records": kept, "count": len(kept),
                                "updated_at": pruned_at})
    return {"before": len(records), "after": len(kept), "expired": len(expired),
            "overflow": len(overflow), "archived": len(removed),
            "archive": str(kb_file.with_suffix(".archive.jsonl"))}
