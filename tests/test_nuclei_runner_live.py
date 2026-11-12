#!/usr/bin/env python3
"""End-to-end local-only test of the real NucleiRunner and ToolRunner."""
from __future__ import annotations

import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.app_profile import AppProfile
from engine.artifacts import ArtifactStore
from engine.nuclei_runner import NucleiRunner
from engine.scope import Scope
from engine.timeguard import TimeWindowGuard
from nuclei_fixture_server import make_server


def main() -> int:
    if not shutil.which("nuclei"):
        print("SKIP: nuclei unavailable")
        return 0
    server, thread = make_server("positive")
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        audit = tempfile.mkdtemp()
        scope = Scope(authorization="local-fixture-only")
        scope.add_in_scope("127.0.0.1", "ip")
        scope.save(Path(audit) / ".pentest-state" / "scope.json")
        TimeWindowGuard(audit).configure([], "UTC",
            (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        app = AppProfile(target=target, tech_stack={"backend": ["python", "fastapi"],
            "frameworks": ["fastapi"]})
        app.architecture.update({"style": "monolith", "frontend_rendering": "spa"})
        result = NucleiRunner(audit).run(target, app, "LOCAL-FIXTURE", rate_limit=2,
                                        concurrency=1, timeout=120)
        assert result["status"] == "completed", result
        assert "fastapi-openapi-documentation" in {item["template_id"] for item in result["leads"]}
        assert ArtifactStore(audit).verify()["intact"]
        print(f"OK: real runner completed with {result['lead_count']} deduplicated leads and intact artifacts")
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
