"""Fix suggestion pipeline — generates remediation snippets per finding.

Maps vuln classes to parameterized fix templates across languages and
frameworks. Produces actionable code/config patches for blue team handoff.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class FixSuggestion:
    vuln_class: str
    language: str = ""
    fix_type: str = ""       # code | config | header | policy
    description: str = ""
    snippet: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "medium"  # high | medium | low


VULN_FIX_PATTERNS: dict[str, list[dict]] = {
    "sqli": [
        {
            "language": "python", "fix_type": "code", "confidence": "high",
            "description": "Use parameterized queries instead of string concatenation.",
            "snippet": (
                "# BEFORE (vulnerable):\n"
                "# cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
                "\n"
                "# AFTER (safe):\n"
                "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"],
        },
        {
            "language": "javascript", "fix_type": "code", "confidence": "high",
            "description": "Use parameterized queries with prepared statements.",
            "snippet": (
                "// BEFORE (vulnerable):\n"
                "// db.query(`SELECT * FROM users WHERE id = ${userId}`);\n"
                "\n"
                "// AFTER (safe):\n"
                "db.query('SELECT * FROM users WHERE id = $1', [userId]);"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"],
        },
    ],
    "xss": [
        {
            "language": "python", "fix_type": "code", "confidence": "high",
            "description": "Apply context-aware output encoding.",
            "snippet": (
                "from markupsafe import escape\n"
                "\n"
                "# In templates: {{ user_input }} (auto-escaped in Jinja2)\n"
                "# In code: escape(user_input)"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        },
        {
            "language": "javascript", "fix_type": "code", "confidence": "high",
            "description": "Use textContent instead of innerHTML; sanitize with DOMPurify for rich content.",
            "snippet": (
                "// BEFORE (vulnerable):\n"
                "// element.innerHTML = userInput;\n"
                "\n"
                "// AFTER (safe):\n"
                "element.textContent = userInput;\n"
                "// Or for rich content:\n"
                "element.innerHTML = DOMPurify.sanitize(userInput);"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        },
    ],
    "xss-stored": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Sanitize on input, encode on output. Store sanitized version.",
            "snippet": (
                "# 1. Validate/sanitize input before storage\n"
                "# 2. Apply context-aware output encoding on every render\n"
                "# 3. Set Content-Security-Policy header to block inline scripts"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        },
    ],
    "csrf": [
        {
            "language": "generic", "fix_type": "header", "confidence": "high",
            "description": "Implement anti-CSRF tokens on all state-changing endpoints.",
            "snippet": (
                "# Framework-specific:\n"
                "# Django: {% csrf_token %} in forms (enabled by default)\n"
                "# Express: csurf middleware\n"
                "# Rails: protect_from_forgery with: :exception\n"
                "\n"
                "# Also set SameSite=Strict on session cookies:\n"
                "Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
        },
    ],
    "ssrf": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Implement URL allowlist validation; block internal/private IP ranges.",
            "snippet": (
                "import ipaddress\n"
                "\n"
                "BLOCKED_RANGES = [\n"
                "    ipaddress.ip_network('10.0.0.0/8'),\n"
                "    ipaddress.ip_network('172.16.0.0/12'),\n"
                "    ipaddress.ip_network('192.168.0.0/16'),\n"
                "    ipaddress.ip_network('169.254.0.0/16'),\n"
                "    ipaddress.ip_network('127.0.0.0/8'),\n"
                "]\n"
                "\n"
                "def is_safe_url(url):\n"
                "    resolved = socket.getaddrinfo(parsed.hostname, None)\n"
                "    for _, _, _, _, addr in resolved:\n"
                "        ip = ipaddress.ip_address(addr[0])\n"
                "        if any(ip in net for net in BLOCKED_RANGES):\n"
                "            return False\n"
                "    return True"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
        },
    ],
    "idor": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Enforce authorization checks on every object access.",
            "snippet": (
                "# BEFORE (vulnerable):\n"
                "# obj = Model.objects.get(id=request.params['id'])\n"
                "\n"
                "# AFTER (safe):\n"
                "obj = Model.objects.get(id=request.params['id'])\n"
                "if obj.owner_id != request.user.id:\n"
                "    raise PermissionDenied()"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
        },
    ],
    "open-redirect": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Validate redirect targets against an allowlist of trusted domains.",
            "snippet": (
                "ALLOWED_HOSTS = {'example.com', 'app.example.com'}\n"
                "\n"
                "def safe_redirect(url):\n"
                "    parsed = urllib.parse.urlparse(url)\n"
                "    if parsed.hostname not in ALLOWED_HOSTS:\n"
                "        return redirect('/')\n"
                "    return redirect(url)"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
        },
    ],
    "file-upload": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Validate file type by content (magic bytes), not extension. Store outside webroot.",
            "snippet": (
                "import magic\n"
                "\n"
                "ALLOWED_TYPES = {'image/png', 'image/jpeg', 'application/pdf'}\n"
                "MAX_SIZE = 10 * 1024 * 1024  # 10 MB\n"
                "\n"
                "def validate_upload(file_bytes, filename):\n"
                "    mime = magic.from_buffer(file_bytes[:2048], mime=True)\n"
                "    if mime not in ALLOWED_TYPES:\n"
                "        raise ValueError(f'Disallowed file type: {mime}')\n"
                "    if len(file_bytes) > MAX_SIZE:\n"
                "        raise ValueError('File too large')\n"
                "    # Store with random name outside webroot\n"
                "    safe_name = f'{uuid.uuid4().hex}{Path(filename).suffix}'"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
        },
    ],
    "jwt-none-algo": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Explicitly specify allowed algorithms when verifying JWTs.",
            "snippet": (
                "# Python (PyJWT):\n"
                "jwt.decode(token, key, algorithms=['HS256'])  # NOT algorithms=['none']\n"
                "\n"
                "# Node.js (jsonwebtoken):\n"
                "jwt.verify(token, secret, { algorithms: ['HS256'] });"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
        },
    ],
    "jwt-weak-secret": [
        {
            "language": "generic", "fix_type": "config", "confidence": "high",
            "description": "Use a cryptographically random secret of at least 256 bits, or switch to RS256.",
            "snippet": (
                "# Generate a strong secret:\n"
                "import secrets\n"
                "JWT_SECRET = secrets.token_hex(32)  # 256-bit random\n"
                "\n"
                "# Or switch to asymmetric (RS256):\n"
                "# Sign with private key, verify with public key"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
        },
    ],
    "cors-misconfiguration": [
        {
            "language": "generic", "fix_type": "header", "confidence": "high",
            "description": "Set explicit allowed origins; never reflect Origin header or use wildcard with credentials.",
            "snippet": (
                "# BEFORE (vulnerable):\n"
                "# Access-Control-Allow-Origin: *\n"
                "# Access-Control-Allow-Credentials: true\n"
                "\n"
                "# AFTER (safe):\n"
                "Access-Control-Allow-Origin: https://app.example.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "Access-Control-Allow-Methods: GET, POST\n"
                "Access-Control-Allow-Headers: Content-Type, Authorization"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
        },
    ],
    "ssti": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Never pass user input as part of a template string. Use sandboxed template engines.",
            "snippet": (
                "# BEFORE (vulnerable):\n"
                "# template = Template(user_input)\n"
                "\n"
                "# AFTER (safe):\n"
                "# Pass user input as a variable, not as the template:\n"
                "template = Template('Hello {{ name }}')\n"
                "result = template.render(name=user_input)\n"
                "\n"
                "# Jinja2: use SandboxedEnvironment\n"
                "from jinja2.sandbox import SandboxedEnvironment\n"
                "env = SandboxedEnvironment()"
            ),
            "references": ["https://portswigger.net/web-security/server-side-template-injection"],
        },
    ],
    "xxe": [
        {
            "language": "generic", "fix_type": "config", "confidence": "high",
            "description": "Disable external entity resolution and DTD processing.",
            "snippet": (
                "# Python (lxml):\n"
                "from lxml import etree\n"
                "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
                "\n"
                "# Java:\n"
                "factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);\n"
                "\n"
                "# PHP:\n"
                "libxml_disable_entity_loader(true);"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
        },
    ],
    "deserialization": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Avoid deserializing untrusted data. Use allowlists for permitted classes.",
            "snippet": (
                "# Python: NEVER use pickle on untrusted input\n"
                "# Use json.loads() instead of pickle.loads()\n"
                "\n"
                "# Java: use ObjectInputFilter (JEP 290)\n"
                "# PHP: avoid unserialize() on user input; use json_decode()"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
        },
    ],
    "mass-assignment": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Explicitly declare which fields are assignable (allowlist).",
            "snippet": (
                "# Django:\n"
                "# Use serializer fields explicitly\n"
                "class UserSerializer(serializers.ModelSerializer):\n"
                "    class Meta:\n"
                "        model = User\n"
                "        fields = ['name', 'email']  # NOT '__all__'\n"
                "\n"
                "# Rails:\n"
                "# params.require(:user).permit(:name, :email)"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
        },
    ],
    "clickjacking": [
        {
            "language": "generic", "fix_type": "header", "confidence": "high",
            "description": "Set X-Frame-Options and Content-Security-Policy frame-ancestors.",
            "snippet": (
                "X-Frame-Options: DENY\n"
                "Content-Security-Policy: frame-ancestors 'none'"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"],
        },
    ],
    "host-header-injection": [
        {
            "language": "generic", "fix_type": "config", "confidence": "high",
            "description": "Validate Host header against an allowlist; never use it to build URLs.",
            "snippet": (
                "# Django: ALLOWED_HOSTS = ['example.com']\n"
                "# Nginx: return 444 for unknown Host values\n"
                "# Generic: never use Host header in password reset URLs"
            ),
            "references": ["https://portswigger.net/web-security/host-header"],
        },
    ],
    "info-disclosure": [
        {
            "language": "generic", "fix_type": "config", "confidence": "medium",
            "description": "Disable debug mode, remove server version headers, customize error pages.",
            "snippet": (
                "# Remove version headers:\n"
                "Server: (remove or set generic)\n"
                "X-Powered-By: (remove)\n"
                "\n"
                "# Disable debug/stack traces in production:\n"
                "# Django: DEBUG = False\n"
                "# Express: app.set('env', 'production')\n"
                "# Rails: config.consider_all_requests_local = false"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"],
        },
    ],
    "rate-limiting": [
        {
            "language": "generic", "fix_type": "config", "confidence": "medium",
            "description": "Implement rate limiting on authentication and sensitive endpoints.",
            "snippet": (
                "# Nginx:\n"
                "limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\n"
                "location /api/login {\n"
                "    limit_req zone=login burst=3 nodelay;\n"
                "}\n"
                "\n"
                "# Application-level: use sliding window counter per user/IP"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"],
        },
    ],
    "lfi": [
        {
            "language": "generic", "fix_type": "code", "confidence": "high",
            "description": "Use an allowlist of permitted file paths; never pass user input to file operations directly.",
            "snippet": (
                "ALLOWED_FILES = {'report.pdf', 'invoice.pdf', 'receipt.pdf'}\n"
                "\n"
                "def get_file(name):\n"
                "    if name not in ALLOWED_FILES:\n"
                "        raise ValueError('File not allowed')\n"
                "    path = SAFE_DIR / name\n"
                "    if not path.resolve().is_relative_to(SAFE_DIR):\n"
                "        raise ValueError('Path traversal detected')\n"
                "    return path.read_bytes()"
            ),
            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
        },
    ],
}


class FixSuggester:
    def suggest_fix(self, finding: dict) -> list[FixSuggestion]:
        vc = finding.get("vuln_class", "").lower().replace("_", "-").replace(" ", "-")
        patterns = VULN_FIX_PATTERNS.get(vc, [])
        if not patterns:
            for key in VULN_FIX_PATTERNS:
                if key in vc or vc in key:
                    patterns = VULN_FIX_PATTERNS[key]
                    break

        return [
            FixSuggestion(
                vuln_class=vc,
                language=p.get("language", "generic"),
                fix_type=p.get("fix_type", "code"),
                description=p.get("description", ""),
                snippet=p.get("snippet", ""),
                references=p.get("references", []),
                confidence=p.get("confidence", "medium"),
            )
            for p in patterns
        ]

    def generate_patch_report(self, findings: list[dict]) -> str:
        lines = [
            "# Remediation Report",
            "",
            f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"> Findings analyzed: {len(findings)}",
            "",
        ]

        by_type: dict[str, list[tuple[dict, FixSuggestion]]] = {}
        no_fix = []

        for f in findings:
            suggestions = self.suggest_fix(f)
            if not suggestions:
                no_fix.append(f)
                continue
            for s in suggestions:
                key = f"{s.fix_type}/{s.language}"
                by_type.setdefault(key, []).append((f, s))

        for key in sorted(by_type):
            fix_type, language = key.split("/", 1)
            lines.append(f"## {fix_type.title()} — {language.title()}")
            lines.append("")
            for finding, suggestion in by_type[key]:
                fid = finding.get("id", "?")
                title = finding.get("title", finding.get("vuln_class", "?"))
                lines.append(f"### {fid}: {title}")
                lines.append("")
                lines.append(f"**Confidence:** {suggestion.confidence}")
                lines.append("")
                lines.append(suggestion.description)
                lines.append("")
                lines.append("```")
                lines.append(suggestion.snippet)
                lines.append("```")
                lines.append("")
                if suggestion.references:
                    lines.append("**References:**")
                    for ref in suggestion.references:
                        lines.append(f"- {ref}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        if no_fix:
            lines.append("## Findings without automated fix suggestions")
            lines.append("")
            for f in no_fix:
                fid = f.get("id", "?")
                vc = f.get("vuln_class", "?")
                lines.append(f"- {fid}: {vc} — manual remediation required")
            lines.append("")

        return "\n".join(lines)
