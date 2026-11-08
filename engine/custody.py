"""Chain of custody for engagement evidence — locally tamper-evident audit trail.

findings.py already hashes each evidence blob (SHA-256). This module adds the
next layer: an append-only, hash-chained event log covering the full
engagement — scope confirmations, evidence capture, status transitions,
exports, operator gates. Each entry includes the hash of the previous entry,
so any post-hoc alteration breaks the chain and is detectable.

This is what makes a report defensible in procurement/legal/compliance
contexts: not just "we found X" but "here is the tamper-evident record of
when, how, and by what authority each action was taken".

Log lives in .pentest-state/custody.jsonl (one JSON object per line).
"""

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from .storage import append_jsonl, read_json
except ImportError:
    from storage import append_jsonl, read_json


GENESIS = "0" * 64


@dataclass
class CustodyEntry:
    event: str            # scope_confirmed | evidence_captured | status_change |
                          # export | operator_gate | retest | note
    detail: dict
    actor: str = "agent"  # agent | operator | engine
    at: str = ""
    prev_hash: str = GENESIS
    entry_hash: str = ""

    def __post_init__(self):
        if not self.at:
            self.at = datetime.now(timezone.utc).isoformat()

    def compute_hash(self) -> str:
        payload = json.dumps({
            "event": self.event, "detail": self.detail, "actor": self.actor,
            "at": self.at, "prev_hash": self.prev_hash,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CustodyLog:
    """Append-only hash-chained custody log for one engagement."""

    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.log_file = self.state_dir / "custody.jsonl"

    def _last_hash(self) -> str:
        if not self.log_file.exists():
            return GENESIS
        last = GENESIS
        with self.log_file.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line).get("entry_hash", GENESIS)
        return last

    def append(self, event: str, detail: dict, actor: str = "agent") -> CustodyEntry:
        # A dedicated lock also works when the caller already holds .lock.
        import fcntl
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with (self.state_dir / ".custody.lock").open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            entry = CustodyEntry(event=event, detail=detail, actor=actor,
                                 prev_hash=self._last_hash())
            entry.entry_hash = entry.compute_hash()
            append_jsonl(self.log_file, asdict(entry))
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return entry

    # Convenience wrappers for the standard events ----

    def scope_confirmed(self, scope_summary: dict) -> CustodyEntry:
        return self.append("scope_confirmed", scope_summary, actor="operator")

    def evidence_captured(self, finding_id: str, evidence_sha256: str, source: str) -> CustodyEntry:
        return self.append("evidence_captured", {
            "finding_id": finding_id, "evidence_sha256": evidence_sha256, "source": source,
        })

    def operator_gate(self, action: str, approved: bool) -> CustodyEntry:
        return self.append("operator_gate", {"action": action, "approved": approved},
                           actor="operator")

    def export(self, fmt: str, path: str, finding_count: int) -> CustodyEntry:
        return self.append("export", {"format": fmt, "path": path,
                                      "finding_count": finding_count})

    def verify(self) -> dict:
        """Walk the chain and confirm integrity. Returns a verification report."""
        prev = GENESIS
        count = 0
        broken_at = None
        if self.log_file.exists():
            with self.log_file.open() as fh:
                for i, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    entry = CustodyEntry(
                        event=rec["event"], detail=rec["detail"],
                        actor=rec.get("actor", "agent"), at=rec["at"],
                        prev_hash=rec.get("prev_hash", GENESIS),
                    )
                    count += 1
                    if entry.prev_hash != prev or entry.compute_hash() != rec.get("entry_hash"):
                        broken_at = i
                        break
                    prev = rec["entry_hash"]
        return {
            "entries": count,
            "intact": broken_at is None,
            "broken_at_line": broken_at,
            "head_hash": prev,
        }

    def command_executed(self, command: str, exit_code: int,
                         output_sha256: str = "", duration_ms: int = 0) -> CustodyEntry:
        """Log a command execution with its hash for audit trail (Gap 16)."""
        cmd_hash = hashlib.sha256(command.encode("utf-8")).hexdigest()
        return self.append("command_executed", {
            "command_hash": cmd_hash,
            "command_preview": command[:200],
            "exit_code": exit_code,
            "output_sha256": output_sha256,
            "duration_ms": duration_ms,
        })

    def evidence_replay_captured(self, finding_id: str, replay_file: str,
                                  request_sha256: str, response_sha256: str) -> CustodyEntry:
        """Log raw HTTP evidence capture for replay (Gap 10)."""
        return self.append("evidence_replay_captured", {
            "finding_id": finding_id,
            "replay_file": replay_file,
            "request_sha256": request_sha256,
            "response_sha256": response_sha256,
        })

    def capture_http_evidence(self, finding_id: str, request_raw: str,
                               response_raw: str, timing_ms: int = 0) -> str:
        """Save raw HTTP request/response pair for replay. Returns path."""
        raw_dir = self.state_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        req_hash = hashlib.sha256(request_raw.encode("utf-8")).hexdigest()
        resp_hash = hashlib.sha256(response_raw.encode("utf-8")).hexdigest()

        replay_id = f"{finding_id}_{req_hash[:12]}"
        replay_file = raw_dir / f"{replay_id}.json"
        replay_file.write_text(json.dumps({
            "finding_id": finding_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "timing_ms": timing_ms,
            "request": request_raw,
            "request_sha256": req_hash,
            "response": response_raw,
            "response_sha256": resp_hash,
        }, indent=2))

        self.evidence_replay_captured(finding_id, str(replay_file),
                                       req_hash, resp_hash)
        return str(replay_file)

    def attestation_block(self) -> str:
        """Markdown block for the engagement report appendix."""
        v = self.verify()
        return (
            f"### Cadena de custodia\n\n"
            f"- Eventos registrados: {v['entries']}\n"
            f"- Integridad de la cadena: {'ÍNTEGRA' if v['intact'] else 'ROTA en línea ' + str(v['broken_at_line'])}\n"
            f"- Hash cabeza (SHA-256): `{v['head_hash']}`\n"
            f"- Log: `.pentest-state/custody.jsonl` (append-only, hash-chained)\n"
        )
