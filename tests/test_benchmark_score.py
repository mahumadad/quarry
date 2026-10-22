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

    # --- version-aware ground truth ---
    from benchmarks.score import applies_to_version, parse_version
    expect(parse_version("20.3.0") == (20, 3, 0), "parse_version básico")
    expect(applies_to_version({"applies_to": "<20"}, "20.3.0") is False, "<20 excluye en v20.3")
    expect(applies_to_version({"applies_to": "<20"}, "19.9.0") is True, "<20 incluye en v19")
    expect(applies_to_version({"applies_to": ">=15,<20"}, "17.0.0") is True, "rango AND incluye")
    expect(applies_to_version({"applies_to": ">=15,<20"}, "21.0") is False, "rango AND excluye alto")
    expect(applies_to_version({}, "20.3.0") is True, "sin constraint siempre aplica")
    expect(applies_to_version({"applies_to": "<20"}, None) is True, "sin versión todo aplica (compat)")

    target_v = d / "target_versioned.yaml"
    target_v.write_text("""name: fixture-versioned
expected:
  - id: fv-sqli
    vuln_class: sqli
    severity: high
    keywords: [login, sql]
  - id: fv-xxe
    vuln_class: xxe
    severity: high
    keywords: [xxe]
    applies_to: "<20"
""")
    rv = score(str(target_v), str(findings), target_version="20.3.0")
    expect(rv["expected_total"] == 1, "v20.3: solo 1 expected aplicable")
    expect(rv["excluded"] and rv["excluded"][0]["expected_id"] == "fv-xxe",
           "xxe excluido con razón auditable")
    expect(abs(rv["recall_required"] - 1.0) < 0.01,
           "recall_required = 1.0 (el único requerido aplicable fue hallado)")
    expect(rv["target_version"] == "20.3.0", "versión registrada en el resultado")

    rv_none = score(str(target_v), str(findings))
    expect(rv_none["expected_total"] == 2, "sin --target-version todo aplica (compat)")

    # --- un finding no puede cubrir dos expected distintos ---
    target_dup = d / "target_dup.yaml"
    target_dup.write_text("""name: fixture-dup
expected:
  - id: fd-xss-dom
    vuln_class: xss
    severity: medium
    keywords: [xss]
  - id: fd-xss-stored
    vuln_class: xss
    severity: high
    keywords: [xss, stored]
""")
    findings_one = d / "findings_one.json"
    findings_one.write_text(json.dumps({"findings": [
        {"id": "F-X", "title": "XSS reflejado", "description": "xss",
         "vuln_class": "xss", "status": "validated", "evidence": []},
    ]}))
    rd = score(str(target_dup), str(findings_one))
    expect(rd["found"] == 1, "un solo expected satisfecho por un solo finding")
    expect(abs(rd["recall_required"] - 0.5) < 0.01,
           "recall_required = 0.5 (el segundo expected queda miss honesto)")

    print(f"\nRESULTS: {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
