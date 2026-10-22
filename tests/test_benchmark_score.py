#!/usr/bin/env python3
"""Self-test for benchmarks/score.py using a synthetic fixture.

Run: python3 tests/test_benchmark_score.py
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.score import score  # noqa: E402


def main() -> int:
    d = Path(tempfile.mkdtemp())

    target = d / "target.yaml"
    target.write_text("""name: fixture
expected:
  - id: fix-sqli
    vuln_class: sqli
    severity: high
    keywords: [login, sql]
  - id: fix-xss
    vuln_class: xss
    severity: medium
    keywords: [xss]
  - id: fix-optional
    vuln_class: ssrf
    severity: low
    keywords: [ssrf]
    optional: true
""")

    findings = d / "findings.json"
    findings.write_text(json.dumps({"findings": [
        {"id": "F-1", "title": "SQL injection en login", "description": "sql auth bypass",
         "vuln_class": "sqli", "status": "validated",
         "evidence": [{"content": "req/resp", "sha256": "abc"}]},
        {"id": "F-2", "title": "XSS reflejado", "description": "xss en search",
         "vuln_class": "xss", "status": "validated",
         "evidence": [{"content": "poc"}]},
        {"id": "F-3", "title": "Algo fuera del ground truth", "description": "extra",
         "vuln_class": "cors", "status": "reported", "evidence": []},
    ]}))

    r = score(str(target), str(findings))
    print(json.dumps(r, indent=2))

    failures = []
    def expect(cond, msg):
        if not cond:
            failures.append(msg)
            print(f"  FAIL: {msg}")
        else:
            print(f"  OK: {msg}")

    expect(r["expected_total"] == 3, "3 expected parsed")
    expect(r["found"] == 2, "2 of 3 matched (ssrf optional missed)")
    expect(abs(r["recall"] - 2 / 3) < 0.01, "recall = 0.667")
    expect(abs(r["recall_required"] - 1.0) < 0.01, "required recall = 1.0 (ambos requeridos hallados)")
    expect(abs(r["precision"] - 2 / 3) < 0.01, "precision = 0.667 (1 unmatched)")
    expect(r["evidence"]["total"] == 2 and r["evidence"]["hashed"] == 1,
           "evidence integrity contada")
    expect(r["missed"][0]["expected_id"] == "fix-optional", "missed = opcional")

    print(f"\nRESULTS: {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
