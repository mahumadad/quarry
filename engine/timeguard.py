"""Testing window enforcement.

Rules of engagement define WHEN testing is allowed (business hours, specific
days, maintenance windows). Firing offensive traffic outside the authorized
window is a contract violation — this module makes the window a hard
mechanical constraint, not a note in a doc.

Config: .pentest-state/window.json
  {
    "timezone": "America/Santiago",
    "windows": [
      {"days": ["mon","tue","wed","thu","fri"], "start": "09:00", "end": "18:00"}
    ],
    "expires_at": "2026-11-01T00:00:00-03:00",   // engagement end date
    "allow_override": false                        // operator emergency override
  }

Integration: engine/guard.py consults TimeWindowGuard.is_allowed() before
permitting offensive commands; every block is logged to custody.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo


DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass
class Window:
    days: list[str] = field(default_factory=lambda: DAY_NAMES[:5])
    start: str = "09:00"
    end: str = "18:00"

    def contains(self, dt: datetime) -> bool:
        day = DAY_NAMES[dt.weekday()]
        if self.days and day not in self.days:
            return False
        h, m = map(int, self.start.split(":"))
        start_t = time(h, m)
        h, m = map(int, self.end.split(":"))
        end_t = time(h, m)
        return start_t <= dt.time() <= end_t


class TimeWindowGuard:
    def __init__(self, audit_dir: str):
        self.config_file = Path(audit_dir) / ".pentest-state" / "window.json"
        self._windows: list[Window] = []
        self._expires_at: datetime | None = None
        self._tz = ZoneInfo("UTC")
        self._allow_override = False
        self._configured = self.config_file.exists()
        self._load()

    def _load(self):
        if not self.config_file.exists():
            return
        cfg = json.loads(self.config_file.read_text())
        self._windows = [Window(**w) for w in cfg.get("windows", [])]
        if cfg.get("timezone"):
            self._tz = ZoneInfo(cfg["timezone"])
        if cfg.get("expires_at"):
            self._expires_at = datetime.fromisoformat(cfg["expires_at"])
        self._allow_override = bool(cfg.get("allow_override", False))

    def configure(self, windows: list[dict], timezone: str,
                  expires_at: str = "", allow_override: bool = False) -> None:
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(json.dumps({
            "timezone": timezone, "windows": windows,
            "expires_at": expires_at, "allow_override": allow_override,
        }, indent=2))
        self._configured = True
        self._load()

    def is_allowed(self, at: datetime | None = None) -> tuple[bool, str]:
        """Returns (allowed, reason). Fail-CLOSED when a window config exists
        but nothing matches; fail-OPEN with a warning when no config exists
        (unconfigured engagement — operator should set one)."""
        if not self._configured:
            return True, "no window configured — set .pentest-state/window.json"
        now = (at or datetime.now(self._tz)).astimezone(self._tz)
        if self._expires_at and now > self._expires_at:
            return False, f"engagement expired at {self._expires_at.isoformat()}"
        if not self._windows:
            return True, "no day/hour restrictions (engagement still expiry-bounded)"
        if any(w.contains(now) for w in self._windows):
            return True, "within authorized window"
        return False, (f"outside authorized window ({now.strftime('%a %H:%M %Z')}); "
                       f"windows: {[f'{w.days} {w.start}-{w.end}' for w in self._windows]}")

    def override(self, reason: str) -> tuple[bool, str]:
        """Emergency operator override — only if the ROE allowed it at config time."""
        if not self._allow_override:
            return False, "override not permitted by engagement config"
        return True, f"OVERRIDE ACTIVE: {reason} (must be logged to custody)"

    def status(self) -> dict:
        return {
            "configured": self._configured,
            "windows": [f"{w.days} {w.start}-{w.end}" for w in self._windows],
            "timezone": str(self._tz),
            "expires_at": self._expires_at.isoformat() if self._expires_at else None,
            "allow_override": self._allow_override,
        }
