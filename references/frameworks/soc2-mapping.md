# SOC 2 Type II — Pentest Finding Mapping

> Maps pentest findings to SOC 2 Trust Services Criteria (TSC).
> Use when the target is a SaaS or service organization under SOC 2 audit.

## Trust Services Criteria

### CC1: Control Environment

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| CC1.4 | Commitment to competence | Findings suggesting lack of security awareness (default creds, debug endpoints in prod) |

### CC5: Control Activities

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| CC5.1 | Risk mitigation activities | Absence of WAF, no rate limiting, missing security headers |
| CC5.2 | Technology general controls | Outdated software, unpatched CVEs, weak TLS |

### CC6: Logical & Physical Access

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| CC6.1 | Logical access to protected assets | IDOR, broken access control, privilege escalation |
| CC6.2 | System access restricted/revoked | Stale accounts, unrevoked API keys |
| CC6.3 | New access is authorized | Mass assignment (self-escalation), registration bypass |
| CC6.6 | Restrict external access | Exposed admin panels, unnecessary public services |
| CC6.7 | Restrict data transmission | Data exfiltration paths (SSRF outbound, unrestricted egress) |
| CC6.8 | Prevent unauthorized software | File upload → webshell, RCE |

### CC7: System Operations

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| CC7.1 | Detect configuration changes | No FIM, no alerting on config changes |
| CC7.2 | Monitor for anomalies | No detection of pentest activity, missing SIEM |
| CC7.3 | Evaluate detected events | No incident response during active testing |
| CC7.4 | Respond to identified events | No blocking/containment actions taken |

### CC8: Change Management

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| CC8.1 | Changes authorized/tested/approved | Debug features in production, test endpoints exposed |

### CC9: Risk Mitigation

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| CC9.1 | Identify/assess risk | Unaddressed high-severity findings from prior audits |

### A: Availability

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| A1.1 | Capacity management | DoS via race condition, resource exhaustion |
| A1.2 | Recovery/continuity | No backup validation (via destructive test if authorized) |

### C: Confidentiality

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| C1.1 | Identify confidential information | PII/secrets in responses, API key leaks, info-disclosure |
| C1.2 | Dispose of confidential data | Sensitive data in logs, backups accessible |

### PI: Processing Integrity

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| PI1.1 | Accurate and complete processing | Race conditions affecting financial calculations |
| PI1.4 | Detect processing errors | Business logic flaws (price manipulation, quantity bypass) |

### P: Privacy

| Criteria | Description | Pentest Findings |
|----------|-------------|------------------|
| P6.1 | Disclose data only as authorized | IDOR exposing other users' PII |
| P6.7 | Unauthorized access notified | No detection of mass PII access |
| P8.1 | Accuracy of personal information | Mass assignment allowing PII modification |

## Usage

SOC 2 auditors evaluate controls, not vulnerabilities directly. Frame
each finding as a control gap:

- **Finding:** SQLi in /api/users endpoint
- **SOC 2 mapping:** CC6.1 (logical access not restricted), CC5.2
  (technology controls insufficient), C1.1 (confidential data
  accessible without authorization)
- **Control gap:** Input validation controls insufficient to prevent
  unauthorized data access via injection attacks
