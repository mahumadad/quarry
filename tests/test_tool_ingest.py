"""Tool output becomes OPEN leads (hypotheses), never findings."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.leads import LeadStatus, LeadsStore  # noqa: E402
from engine.tool_ingest import ingest, parse_nuclei_jsonl, parse_sqlmap  # noqa: E402


NUCLEI = "\n".join([
    json.dumps({"template-id": "exposed-env", "info": {"name": "Exposed .env",
                "severity": "high"}, "matched-at": "https://t.example.com/.env"}),
    "not json at all",
    json.dumps({"template-id": "tech-detect", "info": {"name": "Tech",
                "severity": "info"}, "matched-at": "https://t.example.com"}),
])

SQLMAP = """\
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
---
GET parameter 'id' is vulnerable. target URL: http://t.example.com/item?id=1
"""


def test_nuclei_jsonl_normalized_and_skips_malformed():
    leads = parse_nuclei_jsonl(NUCLEI)
    assert len(leads) == 2  # the junk line is skipped
    high = next(l for l in leads if l.vuln_class_hint == "exposed-env")
    assert high.priority == "high"
    assert high.source == "nuclei"
    assert high.target_asset == "https://t.example.com/.env"
    info = next(l for l in leads if l.vuln_class_hint == "tech-detect")
    assert info.priority == "low"  # info -> low


def test_sqlmap_param_block_to_lead():
    leads = parse_sqlmap(SQLMAP)
    assert len(leads) == 1
    lead = leads[0]
    assert lead.vuln_class_hint == "sqli"
    assert "id" in lead.title
    assert "boolean-based blind" in lead.notes
    assert lead.target_asset.startswith("http")


def test_ingested_leads_are_open_not_findings(tmp_path):
    leads = ingest("nuclei", NUCLEI, audit_dir=str(tmp_path), store=True)
    assert all(l.status == LeadStatus.OPEN.value for l in leads)
    # They are persisted as leads — a hypothesis to verify, not a finding.
    stored = LeadsStore(str(tmp_path)).list_open()
    assert len(stored) == 2


def test_unknown_tool_raises():
    import pytest
    with pytest.raises(ValueError):
        ingest("burp", "whatever")
