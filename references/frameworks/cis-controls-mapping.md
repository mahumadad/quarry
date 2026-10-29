# CIS Controls v8 — Pentest Finding Mapping

> Maps pentest findings to CIS Critical Security Controls v8.
> Framework-agnostic; applicable to any target regardless of industry.
> References: cisecurity.org/controls/v8

## Control Mappings

### CIS 1: Inventory and Control of Enterprise Assets

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 1.1 | Establish asset inventory | Undocumented assets discovered during recon |
| 1.2 | Address unauthorized assets | Shadow IT, forgotten subdomains, test environments |

### CIS 2: Inventory and Control of Software Assets

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 2.1 | Establish software inventory | Untracked software versions, unknown frameworks |
| 2.2 | Ensure authorized software | Unauthorized dev tools in production (phpinfo, debug bars) |
| 2.3 | Address unauthorized software | Test endpoints, admin tools not in inventory |

### CIS 3: Data Protection

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 3.1 | Establish data management process | Sensitive data in logs, verbose error messages |
| 3.3 | Configure data access control lists | IDOR, broken access control exposing data |
| 3.6 | Encrypt data on end-user devices | Hardcoded secrets in mobile apps |
| 3.7 | Establish/maintain data classification | PII/secrets without classification labels in API |
| 3.9 | Encrypt data on removable media | Backup files accessible without encryption |
| 3.10 | Encrypt sensitive data in transit | TLS < 1.2, weak ciphers, missing HSTS |
| 3.11 | Encrypt sensitive data at rest | Plaintext passwords/PII in database |

### CIS 4: Secure Configuration

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 4.1 | Establish secure config process | Default configurations, missing hardening |
| 4.2 | Establish network config process | Permissive firewall rules, unnecessary ports |
| 4.3 | Configure automatic session locking | No session timeout, persistent sessions |
| 4.7 | Manage default accounts | Default credentials on production systems |

### CIS 5: Account Management

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 5.1 | Establish account management process | Account enumeration, mass registration |
| 5.2 | Use unique passwords | Credential reuse, common passwords in spray |
| 5.3 | Disable dormant accounts | Stale accounts with active access |
| 5.4 | Restrict admin privileges | Privilege escalation, mass-assignment to admin |

### CIS 6: Access Control Management

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 6.1 | Establish access granting process | Self-service privilege escalation |
| 6.2 | Establish access revoking process | Stale API keys, unrevoked tokens |
| 6.3 | Require MFA for externally-exposed apps | No MFA on public-facing admin |
| 6.4 | Require MFA for remote access | MFA bypass, fallback to SMS-only |
| 6.5 | Require MFA for admin access | Admin without MFA |
| 6.7 | Centralize access control | Inconsistent authz across endpoints |
| 6.8 | Define/maintain RBAC | IDOR, horizontal privilege escalation |

### CIS 7: Continuous Vulnerability Management

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 7.1 | Establish vuln management process | Unpatched CVEs, outdated dependencies |
| 7.2 | Establish remediation process | Prior findings unaddressed |
| 7.4 | Perform automated application patching | Outdated frameworks (Fire/Smoke priority) |
| 7.5 | Perform automated vuln scans | Nuclei/nmap findings not previously detected |
| 7.7 | Remediate detected vulns | Known CVEs in production |

### CIS 8: Audit Log Management

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 8.2 | Collect audit logs | Missing logs for auth events, admin actions |
| 8.5 | Collect detailed audit logs | Insufficient detail in existing logs |
| 8.9 | Centralize audit logs | Log injection, tampered logs |
| 8.11 | Conduct audit log reviews | No detection of attack during pentest |

### CIS 9: Email and Web Browser Protections

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 9.1 | Ensure only approved browsers/clients | XSS exploitable in all browsers |
| 9.2 | Use DNS filtering | SSRF to external, no DNS restriction |
| 9.5 | Implement DMARC | Missing/misconfigured SPF/DKIM/DMARC |

### CIS 10: Malware Defenses

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 10.1 | Deploy anti-malware | File upload → webshell not detected |
| 10.7 | Use behavior-based anti-malware | Reverse shell not blocked |

### CIS 11: Data Recovery

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 11.1 | Establish data recovery practice | Accessible backups, backup files in webroot |
| 11.4 | Protect backup data | Unencrypted backups accessible via path traversal |

### CIS 13: Network Monitoring and Defense

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 13.1 | Centralize security event alerting | No SIEM alerts during pentest |
| 13.3 | Deploy network IDS | Attacks not detected at network level |
| 13.6 | Collect network traffic flow logs | No netflow to correlate SSRF/pivot |
| 13.8 | Deploy network-level IPS | Attacks not blocked at network level |

### CIS 14: Security Awareness and Skills Training

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 14.1 | Establish security awareness program | Social engineering success (if in scope) |
| 14.5 | Train on causes of data exposure | Info-disclosure patterns suggesting lack of awareness |

### CIS 16: Application Software Security

| Sub-control | Description | Pentest Findings |
|-------------|-------------|------------------|
| 16.1 | Establish AppSec process | Prevalence of OWASP Top 10 findings |
| 16.2 | Establish process to accept/address vulns | This pentest engagement itself |
| 16.4 | Establish/manage code-level security | SQLi, XSS, SSTI, deserialization, RCE |
| 16.6 | Establish code maintenance procedures | Outdated dependencies, EOL frameworks |
| 16.7 | Use standard hardening templates | Missing security headers, permissive CORS |
| 16.9 | Train developers in AppSec | Pattern of findings suggesting training gap |
| 16.12 | Implement WAF | No WAF, WAF bypassed |

## Implementation Groups

CIS Controls are divided into 3 Implementation Groups (IGs):

- **IG1** (essential): Controls 1-6 basics — minimum for all orgs
- **IG2** (standard): IG1 + medium-complexity controls for orgs with dedicated IT
- **IG3** (comprehensive): Full control set for orgs with security teams

Map findings to the lowest applicable IG to help the client prioritize.
IG1 failures are the most critical to address.

## Usage

Map each finding to the most specific CIS sub-control:

- **Finding:** XSS-stored in user profile page
- **CIS mapping:** 16.4 (code-level security), 3.3 (data access control),
  9.1 (browser protections)
- **Implementation Group:** IG1 (16.4 is IG1)
- **Remediation priority:** HIGH (IG1 control failure)
