#!/usr/bin/env python3
"""Score a plugin run against benchmark ground truth.

Compares an engagement's findings.json against a target YAML's expected
findings and emits recall / precision / evidence-integrity metrics.

Usage:
  python3 benchmarks/score.py --target benchmarks/targets/juice-shop.yaml \
      --findings /path/.pentest-state/findings.json --out results/run.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_yaml(path: str) -> dict:
    """Minimal YAML load — use PyYAML if present, else a tiny fallback parser
    sufficient for the targets/*.yaml shape (flat keys + list of dicts)."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(Path(path).read_text())
    except ImportError:
        pass
    data: dict = {"expected": []}
    current: dict | None = None
    for raw in Path(path).read_text().splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.startswith("- id:"):
            current = {"id": line.split(":", 1)[1].strip()}
            data["expected"].append(current)
        elif current is not None and line.strip().endswith(":") is False and ":" in line.strip():
            key, _, val = line.strip().partition(":")
            val = val.strip().strip('"')
            if val.startswith("[") and val.endswith("]"):
                val = [v.strip() for v in val[1:-1].split(",") if v.strip()]
            elif val == "true":
                val = True
            current[key.strip()] = val
        elif ":" in line and current is None:
            key, _, val = line.partition(":")
            data[key.strip()] = val.strip()
    return data


def match_finding(expected: dict, findings: list[dict]) -> dict | None:
    """A run finding matches an expected item when vuln_class matches AND any
    keyword appears in title+description (case-insensitive)."""
    keywords = [k.lower() for k in expected.get("keywords", [])]
    exp_class = (expected.get("vuln_class") or "").lower().replace("hunt-", "")
    for f in findings:
        f_class = (f.get("vuln_class") or "").lower().replace("hunt-", "")
        if exp_class and f_class and exp_class != f_class:
            continue
        haystack = (f.get("title", "") + " " + f.get("description", "")).lower()
        if not keywords or any(k in haystack for k in keywords):
            return f
    return None


def score(target_path: str, findings_path: str) -> dict:
    target = load_yaml(target_path)
    expected = [e for e in target.get("expected", []) if isinstance(e, dict)]
    store = json.loads(Path(findings_path).read_text())
    findings = store.get("findings", [])

    # only validated/reported findings count toward recall — leads are not results
    shippable = [f for f in findings if f.get("status") in ("validated", "reported")]
    considered = shippable or findings  # fallback: if nothing reached validated, score all

    found, missed, matched_ids = [], [], set()
    for e in expected:
        m = match_finding(e, considered)
        if m:
            found.append({"expected_id": e.get("id"), "finding_id": m.get("id"),
                          "optional": bool(e.get("optional"))})
            matched_ids.add(m.get("id"))
        else:
            missed.append({"expected_id": e.get("id"),
                           "vuln_class": e.get("vuln_class"),
                           "severity": e.get("severity"),
                           "optional": bool(e.get("optional"))})

    required = [e for e in expected if not e.get("optional")]
    required_found = [f for f in found
                      if not any(m["expected_id"] == f["expected_id"] and m["optional"]
                                 for m in missed)]

    # precision: reported findings that matched ground truth vs all shippable
    unmatched = [f for f in considered if f.get("id") not in matched_ids]

    # evidence integrity: % of matched findings whose evidence all carry hashes
    ev_total = ev_hashed = 0
    for f in considered:
        for ev in f.get("evidence", []):
            ev_total += 1
            if ev.get("sha256"):
                ev_hashed += 1

    n_req = len(required) or 1
    recall = len(found) / max(len(expected), 1)
    recall_required = len(required_found) / n_req
    precision = len(matched_ids) / max(len(considered), 1)

    return {
        "target": target.get("name"),
        "scored_at": datetime.now(timezone.utc).isoformat(),
        "expected_total": len(expected),
        "expected_required": len(required),
        "found": len(found),
        "missed": missed,
        "recall": round(recall, 3),
        "recall_required": round(recall_required, 3),
        "precision": round(precision, 3),
        "reported_findings": len(considered),
        "unmatched_findings": [{"id": f.get("id"), "title": f.get("title")}
                               for f in unmatched],
        "evidence": {"total": ev_total, "hashed": ev_hashed,
                     "integrity": round(ev_hashed / ev_total, 3) if ev_total else None},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()

    result = score(args.target, args.findings)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
    print(text)

    # exit non-zero if required recall collapsed — usable as CI regression gate
    return 0 if result["recall_required"] >= 0.5 else 1


if __name__ == "__main__":
    sys.exit(main())
