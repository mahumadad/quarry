# PCI DSS 4.0 — Pentest Finding Mapping

> Maps pentest findings to PCI DSS 4.0 requirements.
> Use when the target processes, stores, or transmits cardholder data.

## Relevant Requirements

### Req 1: Network Security Controls

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 1.2.1 | Restrict inbound/outbound traffic | Open ports beyond business need, permissive firewall rules |
| 1.2.5 | No direct public access to CDE | SSRF to internal CDE, exposed management interfaces |
| 1.3.1 | Restrict inbound CDE traffic | Port scan revealing unnecessary services in CDE |
| 1.3.2 | Restrict outbound CDE traffic | OAST callbacks from CDE systems (data exfil path) |
| 1.4.2 | Inbound traffic to DMZ only | Direct access to CDE bypassing DMZ |

### Req 2: Secure Configuration

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 2.2.1 | Change vendor defaults | Default credentials on any CDE system |
| 2.2.2 | Disable unnecessary services | Exposed debug endpoints, unnecessary open ports |
| 2.2.7 | Encrypt non-console admin access | Unencrypted admin panels (HTTP, Telnet) |

### Req 3: Protect Stored Account Data

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 3.3.1 | SAD not stored after auth | Full track data, CVV in DB/logs (via SQLi, log exposure) |
| 3.4.1 | PAN rendered unreadable | PAN in plaintext in DB, API responses, logs |
| 3.5.1 | Key management procedures | Hardcoded encryption keys, key in source code |

### Req 4: Encrypt Transmission

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 4.2.1 | Strong crypto for PAN transmission | TLS < 1.2, weak ciphers, missing HSTS |
| 4.2.1.1 | Trusted certificates | Self-signed certs, expired certs, weak key size |
| 4.2.2 | PAN secured when sent via messaging | PAN in email/chat/SMS via info-disclosure |

### Req 5: Malware Protection

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 5.2.3 | AV on all applicable systems | File upload → webshell execution (no AV catch) |
| 5.3.3 | AV cannot be disabled by users | Disable AV via RCE/privilege escalation |

### Req 6: Secure Development

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 6.2.4 | Address common vulnerabilities | SQLi, XSS, CSRF, SSRF, deserialization — OWASP Top 10 |
| 6.3.1 | Public vuln identification (CVEs) | Outdated components with known CVEs |
| 6.4.1 | Attack detection on public apps | WAF bypass, no detection of attack patterns |
| 6.4.2 | Automated attack detection | No rate limiting, no brute-force protection |

### Req 7: Restrict Access

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 7.2.1 | Access based on business need | IDOR, horizontal/vertical privilege escalation |
| 7.2.2 | Appropriate privileges assigned | Mass assignment, admin access without need |
| 7.2.4 | Review access periodically | Stale accounts with CDE access |

### Req 8: Identify and Authenticate

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 8.2.1 | Unique ID for each user | Shared accounts discovered |
| 8.3.1 | MFA for CDE access | No MFA on admin/CDE-facing apps |
| 8.3.4 | Lockout after failed attempts | No lockout, successful credential spray |
| 8.3.6 | Password complexity / min 12 chars | Weak password policy (NIST 800-63B violations) |
| 8.6.2 | No hardcoded passwords in files | API keys, passwords in source/config |

### Req 10: Logging and Monitoring

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 10.2.1 | Log all access to CDE | Missing audit logs for sensitive operations |
| 10.3.1 | Protect logs from modification | Log injection, log deletion via RCE |
| 10.4.1 | Review logs daily | No detection of attack during pentest |
| 10.7.1 | Respond to failures promptly | Detection rules not firing (see detection_rules.py) |

### Req 11: Regular Testing

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 11.3.1 | Internal vuln scanning quarterly | Findings in internal scan scope |
| 11.3.2 | External vuln scanning quarterly | External-facing findings |
| 11.4.1 | Pentest annually + after changes | This engagement itself |
| 11.4.3 | Segmentation testing every 6 months | SSRF/pivot from non-CDE to CDE |
| 11.5.1 | Intrusion detection (IDS/IPS) | Attacks not detected during testing |

### Req 12: Organizational Policies

| Sub-req | Description | Pentest Findings |
|---------|-------------|------------------|
| 12.10.1 | Incident response plan | No response to active exploitation |

## Usage

When generating a PCI DSS compliance report, map each finding to the
most specific sub-requirement. A finding may map to multiple requirements.
Include the sub-requirement number in the finding's `metadata.compliance`
field and in the report appendix.
