"""Tool output becomes OPEN leads (hypotheses), never findings."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engine.leads import LeadStatus, LeadsStore  # noqa: E402
from engine.tool_ingest import (ingest, parse_bbot, parse_burp,  # noqa: E402
                                parse_ffuf, parse_httpx, parse_nmap,
                                parse_nuclei_jsonl, parse_sqlmap)


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


# --- recon tool ingestion (nmap / httpx / ffuf / bbot) -------------------
#
# Recon output is surface, not a verdict: an open port, a live URL, a found
# path or a bbot event enters as an OPEN lead to investigate, never a finding.

NMAP = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX -">
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <hostnames><hostname name="t.example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/>
        <service name="http-proxy" product="Jetty" version="9.4.43"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/>
        <service name="https"/></port>
    </ports>
  </host>
</nmaprun>
"""

HTTPX = "\n".join([
    json.dumps({"url": "https://t.example.com", "status_code": 200,
                "title": "Admin Portal", "webserver": "Jetty",
                "tech": ["Jetty", "React"], "host": "1.2.3.4"}),
    "not json",
    json.dumps({"url": "https://t.example.com/api", "status_code": 401,
                "tech": ["nginx"]}),
])

FFUF = json.dumps({"results": [
    {"input": {"FUZZ": "admin"}, "url": "https://t.example.com/admin",
     "status": 200, "length": 1234, "words": 100, "lines": 50},
    {"input": {"FUZZ": "backup"}, "url": "https://t.example.com/backup",
     "status": 403, "length": 12, "words": 2, "lines": 1},
]})

BBOT = "\n".join([
    json.dumps({"type": "URL", "data": "https://t.example.com/login",
                "scope_distance": 0, "tags": ["in-scope"]}),
    json.dumps({"type": "VULNERABILITY", "scope_distance": 0,
                "data": {"host": "t.example.com", "severity": "HIGH",
                         "description": "SQLi in id param",
                         "url": "https://t.example.com/x"}}),
    json.dumps({"type": "FINDING", "scope_distance": 0,
                "data": {"host": "t.example.com",
                         "description": "Verbose error leak"}}),
    json.dumps({"type": "OPEN_TCP_PORT", "data": "t.example.com:8080",
                "scope_distance": 0}),
    "not json at all",
    json.dumps({"type": "DNS_NAME", "data": "vendor.example.net",
                "scope_distance": 2}),
])


def test_nmap_open_ports_to_leads():
    leads = parse_nmap(NMAP)
    assert len(leads) == 2  # only open ports; the closed 443 is dropped
    assert all(l.source == "nmap" for l in leads)
    assert not any("443" in l.target_asset for l in leads)
    http = next(l for l in leads if "8080" in l.target_asset)
    assert "Jetty" in http.notes
    assert http.target_asset.startswith("t.example.com")  # hostname over IP


def test_nmap_malformed_returns_empty():
    assert parse_nmap("not xml <<<") == []


def test_httpx_jsonl_to_leads_skips_malformed():
    leads = parse_httpx(HTTPX)
    assert len(leads) == 2  # the junk line is skipped
    assert all(l.source == "httpx" for l in leads)
    api = next(l for l in leads if l.target_asset.endswith("/api"))
    assert "401" in api.title or "401" in api.notes
    root = next(l for l in leads if l.target_asset == "https://t.example.com")
    assert "Jetty" in root.notes


def test_ffuf_results_to_leads():
    leads = parse_ffuf(FFUF)
    assert len(leads) == 2
    assert all(l.source == "ffuf" for l in leads)
    admin = next(l for l in leads if "/admin" in l.target_asset)
    assert admin.priority == "medium"  # 2xx hit is worth a look
    assert "200" in admin.title or "200" in admin.notes
    backup = next(l for l in leads if "/backup" in l.target_asset)
    assert backup.priority == "low"  # 403 is lower-signal


def test_ffuf_malformed_returns_empty():
    assert parse_ffuf("not json") == []


def test_bbot_filters_by_scope_distance():
    leads = parse_bbot(BBOT)  # default keeps only in-scope (distance 0)
    assert len(leads) == 4  # URL, VULNERABILITY, FINDING, OPEN_TCP_PORT
    assert all(l.source == "bbot" for l in leads)
    assert not any("vendor.example.net" in l.target_asset for l in leads)
    vuln = next(l for l in leads if l.vuln_class_hint)
    assert vuln.priority == "high"  # VULNERABILITY severity HIGH -> high
    # Widening the scope distance pulls in the distant DNS_NAME event.
    wider = parse_bbot(BBOT, max_scope_distance=2)
    assert len(wider) == 5
    assert any("vendor.example.net" in l.target_asset for l in wider)


def test_recon_ingested_leads_are_open(tmp_path):
    leads = ingest("nmap", NMAP, audit_dir=str(tmp_path), store=True)
    assert leads and all(l.status == LeadStatus.OPEN.value for l in leads)
    assert len(LeadsStore(str(tmp_path)).list_open()) == 2


def test_unknown_tool_raises():
    # "burp" is a registered tool now; use a genuinely unknown one.
    import pytest
    with pytest.raises(ValueError):
        ingest("nessus", "whatever")
