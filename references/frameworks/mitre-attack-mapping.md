# MITRE ATT&CK Mapping for Common Pentest Findings

Quick reference to tag findings with an ATT&CK tactic and technique ID (Enterprise matrix).

## How to use this table
- ATT&CK describes adversary behavior, not vulnerabilities. A finding maps to the technique an attacker would use to abuse it. Pick the technique your evidence actually demonstrates, not the worst-case follow-on.
- Where no technique fits cleanly, the entry is marked "(approx.)". Say so in the report instead of forcing a mapping.
- Technique IDs and names change between ATT&CK releases. Verify against the current version at https://attack.mitre.org before delivering a report.
- Use the sub-technique (Txxxx.yyy) when the evidence supports it; otherwise use the parent.
- Mapping does not change severity or claim level. Keep the Demonstrated / Inferred / Unproven label from the finding.

## Web application and API vulnerabilities

| Finding Type | Tactic | Technique ID | Name |
|---|---|---|---|
| SQL injection | Initial Access | T1190 | Exploit Public-Facing Application |
| Command injection / OS command execution | Execution | T1059 | Command and Scripting Interpreter |
| Remote code execution in an internet-facing service | Initial Access | T1190 | Exploit Public-Facing Application |
| Server-side template injection (with code execution) | Initial Access | T1190 | Exploit Public-Facing Application |
| Insecure deserialization (with code execution) | Initial Access | T1190 | Exploit Public-Facing Application |
| XML external entity (XXE) file read | Collection | T1005 | Data from Local System |
| XXE / SSRF reaching internal services | Discovery | T1046 | Network Service Discovery (approx.) |
| Server-side request forgery (SSRF) | Initial Access | T1190 | Exploit Public-Facing Application |
| SSRF to cloud metadata service | Credential Access | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API |
| Stored XSS (script runs in victim browser) | Initial Access | T1659 | Content Injection (approx.) |
| Reflected / DOM XSS | Execution | T1059.007 | Command and Scripting Interpreter: JavaScript (approx.) |
| XSS leading to session cookie theft | Credential Access | T1539 | Steal Web Session Cookie |
| XSS leading to in-session actions as victim | Collection | T1185 | Browser Session Hijacking |
| CSRF | Impact | T1565.001 | Data Manipulation: Stored Data Manipulation (approx.) |
| Clickjacking / UI redress | Execution | T1204 | User Execution (approx.) |
| Open redirect (phishing aid) | Initial Access | T1566.002 | Phishing: Spearphishing Link (approx.) |
| IDOR / BOLA (read of other users' data) | Collection | T1213 | Data from Information Repositories (approx.) |
| IDOR / BOLA (modify other users' data) | Impact | T1565.001 | Data Manipulation: Stored Data Manipulation |
| Broken function-level authorization (vertical escalation) | Privilege Escalation | T1068 | Exploitation for Privilege Escalation (approx.) |
| Mass assignment / role field tampering | Persistence | T1098 | Account Manipulation (approx.) |
| Authentication bypass | Initial Access | T1190 | Exploit Public-Facing Application |
| Use of stolen or forged valid session | Defense Evasion | T1550.004 | Use Alternate Authentication Material: Web Session Cookie |
| JWT forgery / signature bypass | Credential Access | T1606 | Forge Web Credentials |
| Stolen or replayed OAuth / API token | Credential Access | T1528 | Steal Application Access Token |
| Insecure file upload leading to web shell | Persistence | T1505.003 | Server Software Component: Web Shell |
| Path traversal / local file inclusion | Collection | T1005 | Data from Local System |
| Remote file inclusion | Execution | T1190 | Exploit Public-Facing Application |
| HTTP request smuggling / cache poisoning | Initial Access | T1659 | Content Injection (approx.) |
| Host header injection / password reset poisoning | Credential Access | T1556 | Modify Authentication Process (approx.) |
| Race condition in business logic (double spend) | Impact | T1565 | Data Manipulation (approx.) |
| Business logic abuse / workflow bypass | Impact | T1565 | Data Manipulation (approx.) |

## Authentication, credentials and access

| Finding Type | Tactic | Technique ID | Name |
|---|---|---|---|
| Default credentials | Initial Access | T1078.001 | Valid Accounts: Default Accounts |
| Weak password policy / guessable passwords | Credential Access | T1110.001 | Brute Force: Password Guessing |
| No lockout / rate limiting on login (password spraying) | Credential Access | T1110.003 | Brute Force: Password Spraying |
| Credential stuffing exposure | Credential Access | T1110.004 | Brute Force: Credential Stuffing |
| Missing multi-factor authentication | Initial Access | T1078 | Valid Accounts |
| Hardcoded secrets in source, JS or config | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files |
| Exposed private keys | Credential Access | T1552.004 | Unsecured Credentials: Private Keys |
| User / account enumeration | Discovery | T1087 | Account Discovery |
| Session fixation / weak session management | Defense Evasion | T1550.004 | Use Alternate Authentication Material: Web Session Cookie |

## Exposure, configuration and recon

| Finding Type | Tactic | Technique ID | Name |
|---|---|---|---|
| Information disclosure: stack traces, verbose errors | Reconnaissance | T1592 | Gather Victim Host Information (approx.) |
| Exposed .git, backups or config files | Collection | T1213.003 | Data from Information Repositories: Code Repositories (approx.) |
| Exposed API documentation / schema | Reconnaissance | T1590 | Gather Victim Network Information (approx.) |
| Exposed admin interface (Plesk, panels, consoles) | Initial Access | T1133 | External Remote Services (approx.) |
| Publicly readable cloud storage | Collection | T1530 | Data from Cloud Storage |
| Subdomain takeover / dangling DNS | Resource Development | T1584.001 | Compromise Infrastructure: Domains |
| Weak TLS / missing HSTS / cleartext transport | Credential Access | T1557 | Adversary-in-the-Middle |
| Missing SPF / DKIM / DMARC (email spoofing) | Defense Evasion | T1672 | Email Spoofing |
| Vulnerable or outdated third-party component | Initial Access | T1190 | Exploit Public-Facing Application |
| Compromised dependency / supply chain exposure | Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| Missing rate limiting / resource exhaustion | Impact | T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood |
| Denial of service via crafted input | Impact | T1499.004 | Endpoint Denial of Service: Application or System Exploitation |

## LLM-specific findings (outside Enterprise ATT&CK)
ATT&CK has no coverage for LLM attack surfaces. Use MITRE ATLAS (https://atlas.mitre.org) and verify IDs against the current release.

| Finding Type | Framework | Technique ID | Name |
|---|---|---|---|
| Direct / indirect prompt injection | ATLAS | AML.T0051 | LLM Prompt Injection |
| Jailbreak of safety controls | ATLAS | AML.T0054 | LLM Jailbreak |

## Reporting notes
- Record one primary mapping per finding and optionally one chained mapping when the chain is Demonstrated.
- Do not map to post-exploitation techniques (lateral movement, exfiltration) unless that behavior was actually demonstrated within scope.
- "Approx." entries signal that the technique is a conventional but imperfect fit; include a one-line justification in the finding.
