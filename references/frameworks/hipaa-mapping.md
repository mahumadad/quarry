# HIPAA Security Rule — Pentest Finding Mapping

> Maps pentest findings to HIPAA Security Rule safeguards.
> Use when the target handles electronic Protected Health Information (ePHI).
> References: 45 CFR Part 160 and Part 164, Subparts A and C.

## Administrative Safeguards (§164.308)

| Standard | Description | Pentest Findings |
|----------|-------------|------------------|
| §164.308(a)(1) | Security management process | Absence of security controls suggesting no formal risk analysis |
| §164.308(a)(3) | Workforce security | Excessive access (IDOR to ePHI), stale accounts with ePHI access |
| §164.308(a)(4) | Information access management | Broken access control, privilege escalation to ePHI |
| §164.308(a)(5) | Security awareness/training | Default credentials, phishing susceptibility, debug endpoints |
| §164.308(a)(6) | Security incident procedures | No detection/response during pentest |
| §164.308(a)(7) | Contingency plan | Accessible backups with ePHI, no encryption on backups |

## Physical Safeguards (§164.310)

| Standard | Description | Pentest Findings |
|----------|-------------|------------------|
| §164.310(b) | Workstation use | Exposed admin interfaces from any network |
| §164.310(d) | Device and media controls | ePHI accessible on decommissioned endpoints |

## Technical Safeguards (§164.312)

| Standard | Description | Pentest Findings |
|----------|-------------|------------------|
| §164.312(a)(1) | Access control | IDOR exposing ePHI, auth-bypass, missing MFA |
| §164.312(a)(2)(i) | Unique user identification | Shared accounts, generic credentials |
| §164.312(a)(2)(ii) | Emergency access procedure | Admin backdoor without audit trail |
| §164.312(a)(2)(iii) | Automatic logoff | Sessions without timeout, persistent tokens |
| §164.312(a)(2)(iv) | Encryption/decryption | ePHI in plaintext in DB, API responses, logs |
| §164.312(b) | Audit controls | Missing audit logs, log injection, no SIEM |
| §164.312(c)(1) | Integrity | SQLi modifying ePHI, mass-assignment changing records |
| §164.312(c)(2) | Authentication of ePHI | Missing HMAC/signature on ePHI in transit |
| §164.312(d) | Person/entity authentication | Weak password policy, no MFA, credential stuffing success |
| §164.312(e)(1) | Transmission security | TLS < 1.2, missing HSTS, weak cipher suites |
| §164.312(e)(2)(i) | Integrity controls in transit | MITM possible (no cert pinning, mixed content) |
| §164.312(e)(2)(ii) | Encryption in transit | ePHI over HTTP, unencrypted API calls |

## Breach Notification Implications (§164.402)

A confirmed finding that exposes ePHI triggers breach analysis:

| Scenario | HIPAA Impact |
|----------|-------------|
| SQLi → ePHI dump | Potential breach requiring notification |
| IDOR → patient records | Potential breach (unsecured PHI accessed) |
| SSRF → internal ePHI service | Potential breach if data accessed |
| API key leak → ePHI API | Potential breach (unauthorized access) |
| XSS → session hijack → ePHI | Potential breach (impersonation + access) |

Exception: if ePHI is encrypted with NIST-approved algorithm and key
not compromised, safe harbor applies (§164.402(2)).

## Usage

Frame findings as safeguard failures:

- **Finding:** IDOR exposing patient records via /api/patients/{id}
- **HIPAA mapping:** §164.312(a)(1) (access control), §164.308(a)(4)
  (information access management)
- **Safeguard gap:** Technical access controls do not enforce
  authorization checks sufficient to prevent unauthorized access to ePHI
- **Breach risk:** HIGH — ePHI accessible without authentication controls,
  no encryption at rest, safe harbor does not apply

Note: pentest does not determine HIPAA compliance — it identifies
technical control gaps that a compliance assessment should evaluate.
