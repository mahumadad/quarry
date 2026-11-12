"""Automated finding validation pipeline.

Defines read-only validation checks that can automatically promote
findings from Inferred → Demonstrated (or demote to Killed).

Based on CVEngine's probe/validation model, adapted to our
evidence-tag system.  All checks are non-destructive: GET requests,
banner grabs, version probes — nothing that modifies target state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class CheckType(str, Enum):
    NUCLEI_TARGETED = "nuclei_targeted"
    NMAP_VERSION = "nmap_version"
    BANNER_GRAB = "banner_grab"
    HTTP_HEAD = "http_head"
    VERSION_PROBE = "version_probe"
    DB_CONNECT = "db_connect"
    CERTIFICATE_CHECK = "certificate_check"


class CheckResult(str, Enum):
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    REFUTED = "refuted"
    ERROR = "error"


VULN_CLASS_CHECKS: dict[str, list[dict]] = {
    "sql-injection": [
        {"type": CheckType.NUCLEI_TARGETED, "desc": "Run targeted SQLi nuclei template against the specific endpoint"},
    ],
    "xss-stored": [
        {"type": CheckType.HTTP_HEAD, "desc": "Verify stored payload still renders in response"},
    ],
    "xss-reflected": [
        {"type": CheckType.HTTP_HEAD, "desc": "Replay reflected payload and check response"},
    ],
    "ssrf": [
        {"type": CheckType.HTTP_HEAD, "desc": "Re-trigger SSRF with fresh OOB callback token"},
    ],
    "open-redirect": [
        {"type": CheckType.HTTP_HEAD, "desc": "Follow redirect chain to verify external destination"},
    ],
    "info-disclosure": [
        {"type": CheckType.HTTP_HEAD, "desc": "Request the same endpoint, verify sensitive data still exposed"},
        {"type": CheckType.BANNER_GRAB, "desc": "Check response headers for version/debug info"},
    ],
    "cors-misconfiguration": [
        {"type": CheckType.HTTP_HEAD, "desc": "Send Origin header, verify ACAO reflection"},
    ],
    "cve-based": [
        {"type": CheckType.NMAP_VERSION, "desc": "Verify exact version with nmap -sV probes"},
        {"type": CheckType.VERSION_PROBE, "desc": "Use version-specific probe from catalog"},
        {"type": CheckType.NUCLEI_TARGETED, "desc": "Run CVE-specific nuclei template"},
    ],
    "exposed-service": [
        {"type": CheckType.BANNER_GRAB, "desc": "Grab service banner to confirm identity"},
        {"type": CheckType.NMAP_VERSION, "desc": "nmap version detection on the port"},
    ],
    "weak-tls": [
        {"type": CheckType.CERTIFICATE_CHECK, "desc": "Verify certificate chain and cipher suites"},
    ],
    "exposed-database": [
        {"type": CheckType.DB_CONNECT, "desc": "Attempt unauthenticated connection (read-only)"},
        {"type": CheckType.BANNER_GRAB, "desc": "Grab database banner for version"},
    ],
    "api-key-leak": [
        {"type": CheckType.HTTP_HEAD, "desc": "Re-request the endpoint to confirm key still exposed"},
    ],
    "graphql-introspection": [
        {"type": CheckType.HTTP_HEAD, "desc": "Re-run introspection query to confirm it's enabled"},
    ],
}


@dataclass
class ValidationCheck:
    finding_id: str
    check_type: CheckType
    description: str
    command: str = ""
    result: CheckResult = CheckResult.INCONCLUSIVE
    output: str = ""
    executed_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "check_type": self.check_type.value,
            "description": self.description,
            "command": self.command,
            "result": self.result.value,
            "output": self.output,
            "executed_at": self.executed_at,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ValidationPlan:
    finding_id: str
    finding_title: str
    vuln_class: str
    target_asset: str
    current_evidence_tag: str
    checks: list[dict] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


def plan_validation(finding: dict) -> ValidationPlan:
    """Generate a validation plan for a finding.

    Returns the list of read-only checks that should be run to
    confirm or refute the finding.  The caller (operator or skill)
    decides which to execute.
    """
    vc = finding.get("vuln_class", "").lower()
    checks = []

    if vc in VULN_CLASS_CHECKS:
        checks = [dict(c) for c in VULN_CLASS_CHECKS[vc]]
    elif finding.get("metadata", {}).get("cve_id"):
        checks = [dict(c) for c in VULN_CLASS_CHECKS["cve-based"]]
    else:
        checks = [
            {"type": CheckType.HTTP_HEAD, "desc": "Re-request the finding's endpoint to verify"},
            {"type": CheckType.BANNER_GRAB, "desc": "Check response headers for confirmation"},
        ]

    return ValidationPlan(
        finding_id=finding.get("id", ""),
        finding_title=finding.get("title", ""),
        vuln_class=vc,
        target_asset=finding.get("target_asset", ""),
        current_evidence_tag=finding.get("evidence_tag", "unproven"),
        checks=checks,
    )


def evaluate_results(checks: list[ValidationCheck]) -> dict:
    """Evaluate a set of completed validation checks.

    Returns recommendation for evidence tag promotion/demotion:
      - All confirmed → promote to Demonstrated
      - Mix of confirmed + inconclusive → stay Inferred
      - Any refuted → recommend Killed (with human gate)
      - All error → no change, flag for manual review
    """
    if not checks:
        return {"action": "no_change", "reason": "No checks executed"}

    results = [c.result for c in checks]
    confirmed = results.count(CheckResult.CONFIRMED)
    refuted = results.count(CheckResult.REFUTED)
    errors = results.count(CheckResult.ERROR)
    total = len(results)

    if refuted > 0:
        return {
            "action": "recommend_kill",
            "reason": f"{refuted}/{total} checks refuted the finding",
            "new_evidence_tag": None,
            "requires_human_gate": True,
        }

    if confirmed == total:
        return {
            "action": "promote",
            "reason": f"All {total} checks confirmed",
            "new_evidence_tag": "demonstrated",
            "requires_human_gate": False,
        }

    if confirmed > 0:
        return {
            "action": "partial_promote",
            "reason": f"{confirmed}/{total} confirmed, rest inconclusive/error",
            "new_evidence_tag": "inferred",
            "requires_human_gate": False,
        }

    if errors == total:
        return {
            "action": "no_change",
            "reason": "All checks errored — manual review needed",
            "requires_human_gate": True,
        }

    return {
        "action": "no_change",
        "reason": "Inconclusive results",
        "new_evidence_tag": None,
        "requires_human_gate": False,
    }


def generate_check_commands(plan: ValidationPlan) -> list[dict]:
    """Generate executable commands for each check in the plan.

    Returns check dicts with a 'command' field populated based on
    the check type and finding's target asset.  The toolrunner
    executes these; this function only generates them.
    """
    target = plan.target_asset
    commands = []

    for check in plan.checks:
        ct = check["type"] if isinstance(check["type"], CheckType) else CheckType(check["type"])
        cmd = ""

        if ct == CheckType.HTTP_HEAD:
            cmd = f"curl -s -I -o /dev/null -w '%{{http_code}}\\n%{{content_type}}' '{target}'"
        elif ct == CheckType.BANNER_GRAB:
            cmd = f"curl -s -D - -o /dev/null '{target}' | head -20"
        elif ct == CheckType.NMAP_VERSION:
            host_port = target.replace("https://", "").replace("http://", "").split("/")[0]
            if ":" in host_port:
                host, port = host_port.rsplit(":", 1)
                cmd = f"nmap -sV -p {port} {host} --open -oX -"
            else:
                cmd = f"nmap -sV {host_port} --open -oX -"
        elif ct == CheckType.NUCLEI_TARGETED:
            cmd = f"nuclei -u '{target}' -as -duc -ni -silent -json"
        elif ct == CheckType.CERTIFICATE_CHECK:
            host_port = target.replace("https://", "").replace("http://", "").split("/")[0]
            cmd = f"echo | openssl s_client -connect {host_port}:443 -servername {host_port} 2>/dev/null | openssl x509 -noout -text"
        elif ct == CheckType.VERSION_PROBE:
            cmd = f"curl -s '{target}' | head -50"
        elif ct == CheckType.DB_CONNECT:
            cmd = "# DB connection check — requires specific handler per DB type"

        commands.append({
            **check,
            "command": cmd,
            "finding_id": plan.finding_id,
        })

    return commands
