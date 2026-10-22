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
    sufficient for the targets/*.yaml shape (top-level keys + indented
    `expected` list of flat dicts)."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(Path(path).read_text())
    except ImportError:
        pass
    data: dict = {"expected": []}
    current: dict | None = None
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        indented = raw.startswith((" ", "\t"))
        if line.startswith("- id:"):
            current = {"id": line.split(":", 1)[1].strip()}
            data["expected"].append(current)
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lstrip("- ").strip(), val.strip()
        if not val:
            continue  # section header: expected:, version_probe:, etc.
        if not indented:
            current = None  # top-level key — leave the expected list
        target = current if (current is not None and indented) else data
        val = val.strip('"').strip("'")
        if val.startswith("[") and val.endswith("]"):
            val = [v.strip() for v in val[1:-1].split(",") if v.strip()]
        elif val == "true":
            val = True
        target[key] = val
    return data


def match_finding(expected: dict, findings: list[dict],
                  taken: set | None = None) -> dict | None:
    """A run finding matches an expected item when vuln_class matches AND any
    keyword appears in title+description (case-insensitive). Findings already
    matched to another expected item are skipped — one real vulnerability
    cannot satisfy two distinct ground-truth entries."""
    keywords = [k.lower() for k in expected.get("keywords", [])]
    exp_class = (expected.get("vuln_class") or "").lower().replace("hunt-", "")
    for f in findings:
        if taken and f.get("id") in taken:
            continue
        f_class = (f.get("vuln_class") or "").lower().replace("hunt-", "")
        if exp_class and f_class and exp_class != f_class:
            continue
        haystack = (f.get("title", "") + " " + f.get("description", "")).lower()
        if not keywords or any(k in haystack for k in keywords):
            return f
    return None


def parse_version(text: str) -> tuple:
    """'20.3.0' -> (20, 3, 0). Non-numeric fragments become 0."""
    parts = []
    for chunk in str(text).strip().lstrip("vV").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def _cmp(a: tuple, b: tuple) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def applies_to_version(item: dict, target_version: str | None) -> bool:
    """Evaluate the item's `applies_to` constraint against the target version.

    Constraint syntax: comma-separated AND of <, <=, >, >=, ==, != comparisons,
    e.g. "<20" (removed in v20+), ">=15,<20" (present in v15–v19 only).
    No constraint or no version known -> applies (backwards compatible)."""
    constraint = str(item.get("applies_to") or "").strip()
    if not constraint or not target_version:
        return True
    v = parse_version(target_version)
    for raw in constraint.split(","):
        raw = raw.strip()
        for op in (">=", "<=", "==", "!=", ">", "<"):
            if raw.startswith(op):
                c = _cmp(v, parse_version(raw[len(op):]))
                ok = {">=": c >= 0, "<=": c <= 0, "==": c == 0,
                      "!=": c != 0, ">": c > 0, "<": c < 0}[op]
                if not ok:
                    return False
                break
        else:
            return True  # unparseable fragment — don't silently exclude
    return True


def probe_target_version(target: dict, base_url: str) -> str | None:
    """Auto-detect the target version via the YAML's version_probe
    (url path + regex with one capture group). Returns None on any failure."""
    probe = target.get("version_probe") or {}
    path, pattern = probe.get("url"), probe.get("regex")
    if not path or not pattern:
        return None
    import re
    import urllib.request
    try:
        with urllib.request.urlopen(base_url.rstrip("/") + path, timeout=5) as r:
            body = r.read().decode(errors="replace")
        m = re.search(pattern, body)
        return m.group(1) if m else None
    except Exception:
        return None


def score(target_path: str, findings_path: str, target_version: str | None = None,
          base_url: str | None = None) -> dict:
    target = load_yaml(target_path)
    all_expected = [e for e in target.get("expected", []) if isinstance(e, dict)]
    store = json.loads(Path(findings_path).read_text())
    findings = store.get("findings", [])

    # version-aware ground truth: items that don't apply to this target version
    # are excluded with an auditable reason instead of inflating the miss list
    if not target_version and base_url:
        target_version = probe_target_version(target, base_url)
    excluded = [{"expected_id": e.get("id"),
                 "applies_to": e.get("applies_to"),
                 "target_version": target_version}
                for e in all_expected if not applies_to_version(e, target_version)]
    expected = [e for e in all_expected if applies_to_version(e, target_version)]

    # only validated/reported findings count toward recall — leads are not results
    shippable = [f for f in findings if f.get("status") in ("validated", "reported")]
    considered = shippable or findings  # fallback: if nothing reached validated, score all

    found, missed, matched_ids = [], [], set()
    for e in expected:
        m = match_finding(e, considered, taken=matched_ids)
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
    required_ids = {e.get("id") for e in required}
    # recall_required: of the REQUIRED ground-truth items, how many were found.
    # An optional find never covers a required miss.
    required_found = [f for f in found if f["expected_id"] in required_ids]

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
        "target_version": target_version,
        "expected_total": len(expected),
        "expected_required": len(required),
        "excluded": excluded,
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
    ap.add_argument("--target-version",
                    help="version del target corrido (p. ej. 20.3.0); filtra el "
                         "ground truth por applies_to")
    ap.add_argument("--base-url",
                    help="URL base del target vivo; si se da y el YAML define "
                         "version_probe, detecta la versión automáticamente")
    args = ap.parse_args()

    result = score(args.target, args.findings,
                   target_version=args.target_version, base_url=args.base_url)
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
