"""Normalize external tool output into LEADS, never into findings.

A tool hit (nuclei match, sqlmap injection point, ...) is a hypothesis, not a
demonstrated finding: it enters the engagement as an OPEN lead that still has
to pass a real oracle (3-gate / the matching hunt skill) before it becomes a
finding. This keeps the anti-fabrication rule intact while getting tool output
into the graph as structured state instead of free text the agent re-types.

Supported tools: ``nuclei`` (JSONL), ``sqlmap`` (console/log text). Add a
parser to INGESTORS to support another.
"""
from __future__ import annotations

import json
import re
from typing import Callable

try:
    from .leads import Lead, LeadsStore
except ImportError:  # top-level script mode
    from leads import Lead, LeadsStore


_NUCLEI_SEVERITY = {
    "critical": "high", "high": "high", "medium": "medium",
    "low": "low", "info": "low", "unknown": "low",
}


def parse_nuclei_jsonl(text: str) -> list[Lead]:
    """One lead per nuclei JSONL result line. Malformed lines are skipped."""
    leads: list[Lead] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        info = rec.get("info", {}) if isinstance(rec.get("info"), dict) else {}
        template = rec.get("template-id") or rec.get("templateID") or ""
        name = info.get("name") or template or "nuclei match"
        severity = str(info.get("severity", "unknown")).lower()
        matched = rec.get("matched-at") or rec.get("host") or rec.get("url") or ""
        leads.append(Lead(
            title=name,
            source="nuclei",
            vuln_class_hint=template,
            target_asset=matched,
            priority=_NUCLEI_SEVERITY.get(severity, "low"),
            notes="nuclei template {} (severity {})".format(template, severity),
        ))
    return leads


_SQLMAP_PARAM = re.compile(r"^Parameter:\s*(.+?)\s*\(([^)]*)\)", re.M)


def parse_sqlmap(text: str) -> list[Lead]:
    """One lead per sqlmap 'Parameter:' injection block."""
    leads: list[Lead] = []
    target = ""
    m_url = re.search(r"https?://[^\s'\"]+", text)
    if m_url:
        target = m_url.group(0)
    for m in _SQLMAP_PARAM.finditer(text):
        param, method = m.group(1).strip(), m.group(2).strip()
        # Capture the injection types listed under this parameter block.
        tail = text[m.end():]
        types = re.findall(r"^\s*Type:\s*(.+)$", tail.split("Parameter:")[0], re.M)
        leads.append(Lead(
            title="SQL injection in '{}' ({})".format(param, method or "param"),
            source="sqlmap",
            vuln_class_hint="sqli",
            target_asset=target,
            priority="high",
            notes="sqlmap types: {}".format(", ".join(t.strip() for t in types)
                                            or "unspecified"),
        ))
    return leads


INGESTORS: dict[str, Callable[[str], list[Lead]]] = {
    "nuclei": parse_nuclei_jsonl,
    "sqlmap": parse_sqlmap,
}


def ingest(tool: str, text: str, audit_dir: str | None = None,
           store: bool = False) -> list[Lead]:
    """Parse ``text`` from ``tool`` into leads; optionally persist them.

    Persisted leads are OPEN — a hypothesis to verify, not a finding. Promotion
    to a finding happens only through a real oracle elsewhere.
    """
    parser = INGESTORS.get(tool)
    if parser is None:
        raise ValueError("unknown tool {!r}; known: {}".format(
            tool, sorted(INGESTORS)))
    leads = parser(text)
    if store and audit_dir:
        leads_store = LeadsStore(audit_dir)
        for lead in leads:
            leads_store.add(lead)
    return leads


def main() -> int:
    import argparse
    from dataclasses import asdict
    from pathlib import Path

    ap = argparse.ArgumentParser(
        prog="engine.tool_ingest",
        description="Normalize tool output (nuclei/sqlmap) into OPEN leads.")
    ap.add_argument("--tool", required=True, choices=sorted(INGESTORS))
    ap.add_argument("--file", required=True, help="tool output file")
    ap.add_argument("--audit-dir", default=".")
    ap.add_argument("--store", action="store_true",
                    help="persist the leads to the engagement's leads store")
    args = ap.parse_args()
    text = Path(args.file).read_text(encoding="utf-8", errors="replace")
    leads = ingest(args.tool, text, audit_dir=args.audit_dir, store=args.store)
    print(json.dumps([asdict(l) for l in leads], indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
