"""Tool output becomes OPEN leads (hypotheses), never findings."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.leads import LeadStatus, LeadsStore  # noqa: E402
from engine.tool_ingest import (ingest, parse_burp, parse_nuclei_jsonl,  # noqa: E402
                                parse_sqlmap)


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

# A real Burp Scanner export carries a DOCTYPE with an internal entity subset;
# the parser must strip it (no entity-expansion bomb) and still read the issues.
BURP = """\
<?xml version="1.0"?>
<!DOCTYPE issues [ <!ENTITY nbsp "&#160;"> ]>
<issues burpVersion="2023.1">
  <issue>
    <name>SQL injection</name>
    <host ip="1.2.3.4">http://t.example.com</host>
    <path><![CDATA[/item]]></path>
    <location><![CDATA[/item [id parameter]]]></location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[background]]></issueBackground>
  </issue>
  <issue>
    <name>Strict transport security not enforced</name>
    <host ip="1.2.3.4">http://t.example.com</host>
    <location><![CDATA[/]]></location>
    <severity>Information</severity>
    <confidence>Certain</confidence>
  </issue>
</issues>
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


def test_burp_scanner_issues_to_leads():
    leads = parse_burp(BURP)
    assert len(leads) == 2  # DOCTYPE stripped, both issues parsed
    sqli = next(l for l in leads if l.vuln_class_hint == "sql-injection")
    assert sqli.source == "burp"
    assert sqli.priority == "high"
    assert sqli.target_asset.startswith("http://t.example.com")
    assert "id parameter" in sqli.target_asset  # host + location joined
    hsts = next(l for l in leads if "transport security" in l.title.lower())
    assert hsts.priority == "low"  # Information -> low


def test_burp_malformed_returns_empty():
    assert parse_burp("not xml at all <<<") == []


def test_burp_ingested_leads_are_open(tmp_path):
    leads = ingest("burp", BURP, audit_dir=str(tmp_path), store=True)
    assert leads and all(l.status == LeadStatus.OPEN.value for l in leads)
    assert len(LeadsStore(str(tmp_path)).list_open()) == 2


def test_unknown_tool_raises():
    # "burp" is a registered tool now; use a genuinely unknown one.
    import pytest
    with pytest.raises(ValueError):
        ingest("nessus", "whatever")
