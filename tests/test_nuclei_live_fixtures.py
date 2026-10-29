#!/usr/bin/env python3
"""Live local fixtures: every template matches positive and rejects controls."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.nuclei_templates import NucleiTemplateCatalog
from nuclei_fixture_server import make_server


def scan(mode: str, records: list[dict]) -> tuple[set[str], str]:
    server, thread = make_server(mode)
    try:
        argv = ["nuclei", "-u", f"http://127.0.0.1:{server.server_port}", "-jsonl",
                "-silent", "-nc", "-dr", "-ni", "-duc", "-no-stdin", "-rl", "20",
                "-c", "2", "-bs", "1", "-retries", "0", "-mhe", "100", "-timeout", "5"]
        for record in records:
            argv.extend(["-t", str(ROOT / "references" / "nuclei-templates" / record["path"])])
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=240)
        ids = set()
        for line in proc.stdout.splitlines():
            try:
                ids.add(json.loads(line).get("template-id", ""))
            except json.JSONDecodeError:
                pass
        return ids, proc.stdout + proc.stderr
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main() -> int:
    if not shutil.which("nuclei"):
        print("SKIP: nuclei unavailable; static tests still required")
        return 0
    records = NucleiTemplateCatalog().load()["templates"]
    expected = {record["id"] for record in records}
    failures = []
    positive, output = scan("positive", records)
    missing = expected - positive
    if missing:
        failures.append(f"positive fixtures missing: {sorted(missing)}")
    for mode in ("negative", "login"):
        matched, control_output = scan(mode, records)
        if matched:
            failures.append(f"{mode} control false positives: {sorted(matched)}")
        output += control_output
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        print(output[-12000:])
        return 1
    print(f"OK: {len(expected)} positive fixtures matched; soft-404 and login controls matched none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
