"""Machine-readable finding exports: SARIF 2.1.0, JSON (ticketing), CSV.

templates/*.md are for humans. These exporters are for pipelines:
  - SARIF  → GitHub/GitLab code scanning, Defender, any SARIF consumer
  - JSON   → Jira/Linear/ServiceNow ticket creation, downstream automation
  - CSV    → spreadsheet triage

Only VALIDATED/REPORTED findings export by default — leads and killed
findings stay out of client-facing machines. Every export is recorded in the
custody log (engine.custody) so the report attestation covers what was
shipped, when, and with how many findings.
"""

import csv
import io
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .findings import FindingsStore, FindingStatus


SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

EXPORTABLE_STATUSES = {FindingStatus.VALIDATED.value, FindingStatus.REPORTED.value}


def _exportable(store: FindingsStore, include_all: bool = False):
    findings = store.list_by_status()
    if include_all:
        return findings
    return [f for f in findings if f.status in EXPORTABLE_STATUSES]


def to_sarif(store: FindingsStore, tool_name: str = "pentest-plugin",
             include_all: bool = False) -> dict:
    """SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html"""
    findings = _exportable(store, include_all)
    rules, results = [], []
    seen_rules = set()
    for f in findings:
        rule_id = f.vuln_class or "unknown"
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": rule_id.replace("-", " ").title(),
                "shortDescription": {"text": rule_id},
                "properties": {
                    "cwe": f.cwe,
                    "mitre_attack": f.mitre_attack,
                },
            })
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(f.severity, "warning"),
            "message": {"text": f"{f.title}\n\n{f.description}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target_asset or "unknown"},
                },
                "logicalLocations": [{"fullyQualifiedName": f.vuln_class}],
            }],
            "partialFingerprints": {"finding_id": f.id},
            "properties": {
                "cvss_vector": f.cvss_vector,
                "cvss_score": f.cvss_score,
                "cvss_version": f.metadata.get("cvss_version", "4.0"),
                "epss_score": f.metadata.get("epss_score"),
                "cisa_kev": f.metadata.get("cisa_kev", False),
                "evidence_tag": f.evidence_tag,
                "status": f.status,
                "steps_to_reproduce": f.steps_to_reproduce,
                "remediation": f.remediation,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/mahumadad/pentest-plugin",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def to_json(store: FindingsStore, include_all: bool = False) -> dict:
    """Ticket-ready JSON: one object per finding, flat, automation-friendly."""
    findings = _exportable(store, include_all)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": [{
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "vuln_class": f.vuln_class,
            "cwe": f.cwe,
            "mitre_attack": f.mitre_attack,
            "target_asset": f.target_asset,
            "description": f.description,
            "impact": f.impact,
            "remediation": f.remediation,
            "steps_to_reproduce": f.steps_to_reproduce,
            "evidence_tag": f.evidence_tag,
            "status": f.status,
            "epss_score": f.metadata.get("epss_score"),
            "cisa_kev": f.metadata.get("cisa_kev", False),
        } for f in findings],
    }


def to_csv(store: FindingsStore, include_all: bool = False) -> str:
    findings = _exportable(store, include_all)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "title", "severity", "cvss_score", "vuln_class",
                     "cwe", "target_asset", "status", "evidence_tag"])
    for f in findings:
        writer.writerow([f.id, f.title, f.severity, f.cvss_score, f.vuln_class,
                         ";".join(f.cwe), f.target_asset, f.status, f.evidence_tag])
    return buf.getvalue()


def export(store: FindingsStore, fmt: str, out_path: str,
           include_all: bool = False, custody=None) -> str:
    """Write an export file and (optionally) record it in the custody log."""
    fmt = fmt.lower()
    if fmt == "sarif":
        content = json.dumps(to_sarif(store, include_all=include_all), indent=2)
    elif fmt == "json":
        content = json.dumps(to_json(store, include_all=include_all), indent=2)
    elif fmt == "csv":
        content = to_csv(store, include_all=include_all)
    else:
        raise ValueError(f"unknown export format: {fmt} (sarif|json|csv)")

    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

    if custody is not None:
        custody.export(fmt=fmt, path=str(path),
                       finding_count=len(_exportable(store, include_all)))
    return str(path)
