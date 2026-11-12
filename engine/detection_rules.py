"""Detection pairing: generate Sigma rules from pentest findings.

Each confirmed finding produces a detection rule the target's blue team
can deploy in their SIEM.  Rules follow the Sigma generic signature
format (https://sigmahq.io/) and map to the finding's MITRE ATT&CK tags.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path


VULN_CLASS_DETECTION_PATTERNS: dict[str, dict] = {
    "sqli": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|contains": ["'", "UNION", "SELECT", "OR 1=1", "--", "SLEEP(", "BENCHMARK("]},
            "selection_body": {"cs-body|contains": ["' OR ", "UNION SELECT", "1=1--", "WAITFOR DELAY"]},
        },
        "condition": "selection_uri or selection_body",
        "false_positive_notes": ["Legitimate queries containing SQL keywords in user content"],
        "level": "high",
    },
    "xss-stored": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_body": {"cs-body|contains": ["<script", "javascript:", "onerror=", "onload=", "<img src=x", "<svg/onload"]},
        },
        "condition": "selection_body",
        "false_positive_notes": ["CMS content editors submitting HTML", "Admin interfaces with rich text"],
        "level": "high",
    },
    "xss-reflected": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|contains": ["<script", "javascript:", "onerror=", "onload=", "alert(", "prompt(", "confirm("]},
        },
        "condition": "selection_uri",
        "false_positive_notes": ["Scanning tools testing for XSS", "Encoded payloads may bypass this rule"],
        "level": "medium",
    },
    "ssrf": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|contains": ["http://169.254.169.254", "http://127.0.0.1", "http://localhost", "http://[::1]", "http://0.0.0.0", "file:///"]},
            "selection_body": {"cs-body|contains": ["169.254.169.254", "127.0.0.1", "localhost", "metadata.google", "metadata.azure"]},
        },
        "condition": "selection_uri or selection_body",
        "false_positive_notes": ["Health check endpoints using localhost references"],
        "level": "critical",
    },
    "idor": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_pattern": {"cs-uri-query|re": ["id=\\d+", "user_id=\\d+", "account=\\d+", "order_id=\\d+"]},
            "selection_rapid": {"count()": "> 20", "timeframe": "1m", "group-by": ["c-ip"]},
        },
        "condition": "selection_pattern and selection_rapid",
        "false_positive_notes": ["Automated testing tools", "Batch processing by legitimate services"],
        "level": "medium",
    },
    "csrf": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_method": {"cs-method": ["POST", "PUT", "DELETE"]},
            "filter_referer": {"Referer|contains": ["{target_domain}"]},
        },
        "condition": "selection_method and not filter_referer",
        "false_positive_notes": ["API clients without Referer header", "Privacy extensions stripping Referer"],
        "level": "medium",
    },
    "rce": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|contains": [";ls", "|cat", "`id`", "$(whoami)", ";ping", "|nc ", "bash -i"]},
            "selection_body": {"cs-body|contains": ["exec(", "system(", "passthru(", "Runtime.getRuntime", "os.popen", "subprocess."]},
        },
        "condition": "selection_uri or selection_body",
        "false_positive_notes": ["Developer debugging endpoints in staging"],
        "level": "critical",
    },
    "ssti": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|contains": ["{{", "${", "#{", "<%= ", "#{7*7}", "{{7*7}}", "${7*7}"]},
            "selection_body": {"cs-body|contains": ["{{", "${", "#{", "__class__", "__mro__", "__subclasses__"]},
        },
        "condition": "selection_uri or selection_body",
        "false_positive_notes": ["Template engines in URLs for legitimate rendering"],
        "level": "critical",
    },
    "xxe": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_body": {"cs-body|contains": ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file:///", "expect://", "php://"]},
            "selection_content_type": {"Content-Type|contains": ["xml"]},
        },
        "condition": "selection_body and selection_content_type",
        "false_positive_notes": ["Legitimate XML uploads with DOCTYPE declarations"],
        "level": "high",
    },
    "lfi": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|contains": ["../", "..\\", "/etc/passwd", "/etc/shadow", "C:\\Windows\\", "....//", "%2e%2e%2f"]},
        },
        "condition": "selection_uri",
        "false_positive_notes": ["Relative path references in legitimate applications"],
        "level": "high",
    },
    "file-upload": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_upload": {"cs-uri|contains": ["upload", "import", "attach"]},
            "selection_ext": {"cs-body|contains": [".php", ".jsp", ".asp", ".aspx", ".phtml", ".svg", ".shtml"]},
        },
        "condition": "selection_upload and selection_ext",
        "false_positive_notes": ["Legitimate file uploads with these extensions in specific workflows"],
        "level": "high",
    },
    "auth-bypass": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_admin": {"cs-uri|contains": ["/admin", "/api/admin", "/internal", "/debug", "/management"]},
            "filter_auth": {"sc-status": [200]},
        },
        "condition": "selection_admin and filter_auth",
        "false_positive_notes": ["Legitimate admin access from authorized IPs"],
        "level": "critical",
    },
    "jwt": {
        "log_source": {"category": "proxy", "product": ""},
        "detection_fields": {
            "selection_header": {"Authorization|contains": ["eyJ"]},
            "selection_alg_none": {"Authorization|re": ["eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.$", "\"alg\":\\s*\"none\""]},
        },
        "condition": "selection_header and selection_alg_none",
        "false_positive_notes": ["Misconfigured JWT libraries in development"],
        "level": "critical",
    },
    "cors-misconfiguration": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_origin": {"Origin|contains": ["evil.com", "attacker.com", "null"]},
            "selection_acao": {"Access-Control-Allow-Origin": ["*"]},
        },
        "condition": "selection_origin or selection_acao",
        "false_positive_notes": ["Wildcard CORS on intentionally public APIs"],
        "level": "medium",
    },
    "open-redirect": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_uri": {"cs-uri-query|re": ["(redirect|url|next|return|goto|dest)=https?://[^/]*[^{target_domain}]"]},
        },
        "condition": "selection_uri",
        "false_positive_notes": ["Legitimate redirect parameters to partner domains"],
        "level": "low",
    },
    "deserialization": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_body": {"cs-body|contains": ["rO0AB", "aced0005", "O:4:", "a:2:{", "pickle.", "__reduce__"]},
            "selection_content_type": {"Content-Type|contains": ["java-serialized", "x-java-object", "application/octet-stream"]},
        },
        "condition": "selection_body or selection_content_type",
        "false_positive_notes": ["Legacy Java applications using native serialization"],
        "level": "critical",
    },
    "mass-assignment": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_body": {"cs-body|contains": ["\"role\":", "\"is_admin\":", "\"admin\":", "\"privilege\":", "\"permissions\":", "\"group\":"]},
            "selection_method": {"cs-method": ["POST", "PUT", "PATCH"]},
        },
        "condition": "selection_body and selection_method",
        "false_positive_notes": ["Admin interfaces legitimately setting role fields"],
        "level": "high",
    },
    "graphql-introspection": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_body": {"cs-body|contains": ["__schema", "__type", "introspectionQuery", "{__typename}"]},
        },
        "condition": "selection_body",
        "false_positive_notes": ["GraphQL IDE tools used by developers"],
        "level": "low",
    },
    "api-key-leak": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_response": {"sc-body|re": ["(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\\s*[=:]\\s*['\"][A-Za-z0-9]{16,}"]},
        },
        "condition": "selection_response",
        "false_positive_notes": ["Documentation pages showing example keys"],
        "level": "high",
    },
    "race-condition": {
        "log_source": {"category": "webserver", "product": ""},
        "detection_fields": {
            "selection_rapid": {"cs-uri": ["{endpoint}"], "count()": "> 10", "timeframe": "2s", "group-by": ["c-ip"]},
        },
        "condition": "selection_rapid",
        "false_positive_notes": ["Automated batch processing", "Load testing"],
        "level": "medium",
    },
}

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
}


def generate_sigma_rule(finding: dict) -> str:
    vc = finding.get("vuln_class", "").lower()
    pattern = VULN_CLASS_DETECTION_PATTERNS.get(vc)
    if not pattern:
        return ""

    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, finding.get("id", "") + vc))
    title = f"Detect {vc.replace('-', ' ').title()} — {finding.get('title', 'Unknown')}"
    if len(title) > 120:
        title = title[:117] + "..."

    description = (
        f"Detects exploitation attempts matching finding {finding.get('id', 'N/A')}: "
        f"{finding.get('title', '')}. Target: {finding.get('target_asset', 'N/A')}."
    )

    mitre_tags = finding.get("mitre_attack", [])
    tags = [f"attack.{t.lower().replace(' ', '_')}" for t in mitre_tags]
    if not tags:
        tags = [f"attack.{_default_mitre_tactic(vc)}"]

    level = SEVERITY_MAP.get(finding.get("severity", "medium"), pattern.get("level", "medium"))
    logsource = pattern["log_source"]
    detection_fields = _resolve_placeholders(pattern["detection_fields"], finding)
    condition = pattern["condition"]
    fps = pattern.get("false_positive_notes", [])

    lines = [
        f"title: {title}",
        f"id: {rule_id}",
        "status: experimental",
        f"description: {description}",
        f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}",
        "logsource:",
    ]
    for k, v in logsource.items():
        if v:
            lines.append(f"    {k}: {v}")
        else:
            lines.append(f"    {k}: webserver")
    lines.append("detection:")
    for sel_name, sel_fields in detection_fields.items():
        lines.append(f"    {sel_name}:")
        for field_name, field_values in sel_fields.items():
            if isinstance(field_values, list):
                lines.append(f"        {field_name}:")
                for val in field_values:
                    lines.append(f"            - '{val}'")
            else:
                lines.append(f"        {field_name}: '{field_values}'")
    lines.append(f"    condition: {condition}")
    if fps:
        lines.append("falsepositives:")
        for fp in fps:
            lines.append(f"    - {fp}")
    lines.append(f"level: {level}")
    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"    - {tag}")

    return "\n".join(lines) + "\n"


def generate_rules_for_engagement(findings: list[dict]) -> list[dict]:
    rules = []
    for f in findings:
        vc = f.get("vuln_class", "").lower()
        if vc not in VULN_CLASS_DETECTION_PATTERNS:
            continue
        status = f.get("status", "")
        if status == "killed":
            continue
        yaml_content = generate_sigma_rule(f)
        if not yaml_content:
            continue
        pattern = VULN_CLASS_DETECTION_PATTERNS[vc]
        rules.append({
            "finding_id": f.get("id", ""),
            "vuln_class": vc,
            "rule_yaml": yaml_content,
            "log_source": pattern["log_source"].get("category", "webserver"),
            "level": pattern.get("level", "medium"),
        })
    return rules


def save_rules(rules: list[dict], output_dir: Path) -> Path:
    rules_dir = output_dir / "detection-rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for rule in rules:
        fname = f"{rule['finding_id']}-{rule['vuln_class']}.yml"
        (rules_dir / fname).write_text(rule["rule_yaml"])
    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule_count": len(rules),
        "rules": [
            {"file": f"{r['finding_id']}-{r['vuln_class']}.yml",
             "finding_id": r["finding_id"],
             "vuln_class": r["vuln_class"],
             "log_source": r["log_source"],
             "level": r["level"]}
            for r in rules
        ],
    }
    import json
    (rules_dir / "index.json").write_text(json.dumps(index, indent=2))
    return rules_dir


def _resolve_placeholders(detection_fields: dict, finding: dict) -> dict:
    import re
    target = finding.get("target_asset", "example.com")
    domain = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
    endpoint = finding.get("target_asset", "/")

    resolved = {}
    for sel_name, sel_fields in detection_fields.items():
        resolved[sel_name] = {}
        for field_name, field_values in sel_fields.items():
            if isinstance(field_values, list):
                resolved[sel_name][field_name] = [
                    v.replace("{target_domain}", domain).replace("{endpoint}", endpoint)
                    for v in field_values
                ]
            elif isinstance(field_values, str):
                resolved[sel_name][field_name] = (
                    field_values.replace("{target_domain}", domain).replace("{endpoint}", endpoint)
                )
            else:
                resolved[sel_name][field_name] = field_values
    return resolved


_MITRE_TACTIC_MAP = {
    "sqli": "initial_access",
    "xss-stored": "persistence",
    "xss-reflected": "initial_access",
    "ssrf": "lateral_movement",
    "idor": "collection",
    "csrf": "execution",
    "rce": "execution",
    "ssti": "execution",
    "xxe": "collection",
    "lfi": "collection",
    "file-upload": "persistence",
    "auth-bypass": "privilege_escalation",
    "jwt": "credential_access",
    "cors-misconfiguration": "collection",
    "open-redirect": "initial_access",
    "deserialization": "execution",
    "mass-assignment": "privilege_escalation",
    "graphql-introspection": "discovery",
    "api-key-leak": "credential_access",
    "race-condition": "impact",
}


def _default_mitre_tactic(vuln_class: str) -> str:
    return _MITRE_TACTIC_MAP.get(vuln_class, "initial_access")
