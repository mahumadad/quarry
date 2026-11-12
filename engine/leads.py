"""Leads ledger — unexplored attack vectors that block engagement closeout.

A lead is an observation, hint, or unexplored vector discovered during recon
or hunting that deserves investigation.  Open leads block closeout: the
operator must close every lead with an explicit reason before the engagement
can be declared complete.
"""

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

try:
    from .custody import CustodyLog
    from .storage import atomic_write_json, engagement_lock, read_json
except ImportError:
    from custody import CustodyLog
    from storage import atomic_write_json, engagement_lock, read_json


class LeadStatus(str, Enum):
    OPEN = "open"
    EXPLORING = "exploring"
    CLOSED = "closed"


class CloseReason(str, Enum):
    EXPLORED = "explored"
    FALSE_POSITIVE = "false-positive"
    DEAD = "dead"
    OUT_OF_SCOPE = "out-of-scope"
    DUPLICATE = "duplicate"
    ESCALATED = "escalated"


VALID_PRIORITIES = {"high", "medium", "low"}


@dataclass
class Lead:
    id: str = ""
    title: str = ""
    source: str = ""
    vuln_class_hint: str = ""
    target_asset: str = ""
    priority: str = "medium"
    status: str = LeadStatus.OPEN.value
    close_reason: str = ""
    notes: str = ""
    created_at: str = ""
    closed_at: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = f"L-{uuid.uuid4().hex[:8].upper()}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


class LeadsStore:
    def __init__(self, audit_dir: str):
        self.state_dir = Path(audit_dir) / ".pentest-state"
        self.leads_file = self.state_dir / "leads.json"
        self._leads: dict[str, Lead] = {}
        self._load()

    def _load(self):
        self._leads = {}
        if self.leads_file.exists():
            data = read_json(self.leads_file)
            for ld in data.get("leads", []):
                lead = Lead(**ld)
                self._leads[lead.id] = lead

    def _save(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.leads_file, {
            "leads": [asdict(l) for l in self._leads.values()],
            "count": len(self._leads),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

    def add(self, lead: Lead) -> Lead:
        with engagement_lock(self.state_dir.parent):
            self._load()
            self._leads[lead.id] = lead
            self._save()
            CustodyLog(self.state_dir.parent).append("lead_created", {
                "lead_id": lead.id, "title": lead.title,
                "source": lead.source, "target_asset": lead.target_asset,
                "priority": lead.priority,
            })
        return lead

    def get(self, lead_id: str) -> Lead | None:
        return self._leads.get(lead_id)

    def close(self, lead_id: str, reason: str, notes: str = "") -> bool:
        CloseReason(reason)
        with engagement_lock(self.state_dir.parent):
            self._load()
            lead = self._leads.get(lead_id)
            if not lead or lead.status == LeadStatus.CLOSED.value:
                return False
            lead.status = LeadStatus.CLOSED.value
            lead.close_reason = reason
            lead.closed_at = datetime.now(timezone.utc).isoformat()
            if notes:
                lead.notes = (lead.notes + " | " + notes).strip(" |") if lead.notes else notes
            self._save()
            CustodyLog(self.state_dir.parent).append("lead_closed", {
                "lead_id": lead_id, "reason": reason,
            })
        return True

    def reopen(self, lead_id: str, reason: str = "") -> bool:
        with engagement_lock(self.state_dir.parent):
            self._load()
            lead = self._leads.get(lead_id)
            if not lead or lead.status != LeadStatus.CLOSED.value:
                return False
            lead.status = LeadStatus.OPEN.value
            lead.close_reason = ""
            lead.closed_at = ""
            if reason:
                lead.notes = (lead.notes + " | reopened: " + reason).strip(" |") if lead.notes else f"reopened: {reason}"
            self._save()
            CustodyLog(self.state_dir.parent).append("lead_reopened", {
                "lead_id": lead_id, "reason": reason,
            })
        return True

    def start_exploring(self, lead_id: str) -> bool:
        with engagement_lock(self.state_dir.parent):
            self._load()
            lead = self._leads.get(lead_id)
            if not lead or lead.status != LeadStatus.OPEN.value:
                return False
            lead.status = LeadStatus.EXPLORING.value
            self._save()
        return True

    def list_open(self) -> list[Lead]:
        return [l for l in self._leads.values() if l.status != LeadStatus.CLOSED.value]

    def list_by_status(self, status: LeadStatus) -> list[Lead]:
        return [l for l in self._leads.values() if l.status == status.value]

    def blocks_closeout(self) -> bool:
        return any(l.status != LeadStatus.CLOSED.value for l in self._leads.values())

    def closeout_report(self) -> dict:
        open_leads = self.list_open()
        closed = self.list_by_status(LeadStatus.CLOSED)
        by_reason: dict[str, int] = {}
        for l in closed:
            by_reason[l.close_reason] = by_reason.get(l.close_reason, 0) + 1
        by_priority: dict[str, int] = {}
        for l in open_leads:
            by_priority[l.priority] = by_priority.get(l.priority, 0) + 1
        return {
            "blocks_closeout": self.blocks_closeout(),
            "total": len(self._leads),
            "open": len(open_leads),
            "closed": len(closed),
            "open_leads": [asdict(l) for l in open_leads],
            "close_reasons": by_reason,
            "open_by_priority": by_priority,
        }

    def summary(self) -> dict:
        by_status: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for l in self._leads.values():
            by_status[l.status] = by_status.get(l.status, 0) + 1
            by_priority[l.priority] = by_priority.get(l.priority, 0) + 1
        return {
            "total": len(self._leads),
            "by_status": by_status,
            "by_priority": by_priority,
            "blocks_closeout": self.blocks_closeout(),
        }
