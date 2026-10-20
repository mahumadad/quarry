# OWASP Mapping for Common Vulnerability Classes

Maps vulnerability classes to three OWASP lists:
1. OWASP Top 10 (2021) for web applications
2. OWASP API Security Top 10 (2023)
3. OWASP Top 10 for LLM Applications (2025)

## How to use this file
- Pick the category that matches the root cause, not the symptom. If two apply, list a primary and a secondary.
- OWASP categories are risk groupings, not severity. A category match does not change the evidence level or rating of the finding.
- "-" means no natural fit. Do not force a mapping.
- Verify names against the current official lists (https://owasp.org/Top10/, https://owasp.org/API-Security/, https://genai.owasp.org) before delivery.

## Reference: OWASP Top 10 2021

| ID | Category |
|---|---|
| A01:2021 | Broken Access Control |
| A02:2021 | Cryptographic Failures |
| A03:2021 | Injection |
| A04:2021 | Insecure Design |
| A05:2021 | Security Misconfiguration |
| A06:2021 | Vulnerable and Outdated Components |
| A07:2021 | Identification and Authentication Failures |
| A08:2021 | Software and Data Integrity Failures |
| A09:2021 | Security Logging and Monitoring Failures |
| A10:2021 | Server-Side Request Forgery (SSRF) |

## Reference: OWASP API Security Top 10 2023

| ID | Category |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

## Reference: OWASP Top 10 for LLM Applications 2025

| ID | Category |
|---|---|
| LLM01:2025 | Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure |
| LLM03:2025 | Supply Chain |
| LLM04:2025 | Data and Model Poisoning |
| LLM05:2025 | Improper Output Handling |
| LLM06:2025 | Excessive Agency |
| LLM07:2025 | System Prompt Leakage |
| LLM08:2025 | Vector and Embedding Weaknesses |
| LLM09:2025 | Misinformation |
| LLM10:2025 | Unbounded Consumption |

## Table 1: Vulnerability class to OWASP Top 10 2021

| Vulnerability Class | OWASP Top 10 2021 | Notes |
|---|---|---|
| SQL injection | A03 Injection | |
| NoSQL / LDAP / OS command injection | A03 Injection | |
| Server-side template injection (SSTI) | A03 Injection | Server-side evaluation must be shown |
| XML external entity (XXE) | A05 Security Misconfiguration | XXE was its own category in 2017; now folded into A05 |
| Cross-site scripting (XSS) | A03 Injection | |
| CSRF | A01 Broken Access Control | Commonly placed here; some teams use A04 |
| IDOR / object-level authorization flaws | A01 Broken Access Control | |
| Missing function-level access control / privilege escalation | A01 Broken Access Control | |
| Path traversal / local file inclusion | A01 Broken Access Control | |
| Open redirect | A01 Broken Access Control | Secondary: A04 Insecure Design |
| CORS misconfiguration | A05 Security Misconfiguration | Secondary: A01 when it exposes authenticated data |
| Authentication bypass / broken login | A07 Identification and Authentication Failures | |
| Weak passwords / default credentials / no lockout | A07 Identification and Authentication Failures | |
| Session management flaws | A07 Identification and Authentication Failures | |
| JWT validation flaws | A07 Identification and Authentication Failures | Secondary: A02 for weak signing secrets |
| Weak TLS / missing encryption of sensitive data | A02 Cryptographic Failures | |
| Hardcoded secrets / keys | A02 Cryptographic Failures | Secondary: A05 |
| Insecure deserialization | A08 Software and Data Integrity Failures | |
| Unsigned updates / insecure CI/CD / untrusted dependencies | A08 Software and Data Integrity Failures | |
| Race condition / business logic flaw | A04 Insecure Design | |
| Missing rate limiting / anti-automation | A04 Insecure Design | Secondary: A07 for login flows |
| Insecure file upload | A04 Insecure Design | Secondary: A05 / A08 depending on cause |
| SSRF | A10 Server-Side Request Forgery | |
| Information disclosure / verbose errors / debug endpoints | A05 Security Misconfiguration | Hardening note unless sensitive data is shown |
| Missing security headers / insecure defaults | A05 Security Misconfiguration | |
| Exposed admin interface / default pages | A05 Security Misconfiguration | |
| Outdated components with verified exploitable CVE | A06 Vulnerable and Outdated Components | Version alone is not a finding |
| Insufficient logging and monitoring | A09 Security Logging and Monitoring Failures | |
| Subdomain takeover | A05 Security Misconfiguration | |
| Missing SPF / DKIM / DMARC | A05 Security Misconfiguration | |

## Table 2: Vulnerability class to OWASP API Security Top 10 2023

| Vulnerability Class | OWASP API Top 10 2023 | Notes |
|---|---|---|
| IDOR / BOLA | API1 Broken Object Level Authorization | Object-level, per resource ID |
| Weak or missing authentication, credential stuffing exposure | API2 Broken Authentication | |
| JWT / token validation flaws | API2 Broken Authentication | |
| Excessive data exposure in responses | API3 Broken Object Property Level Authorization | Merged from 2019 API3 |
| Mass assignment | API3 Broken Object Property Level Authorization | Merged from 2019 API6 |
| Missing rate limiting / no pagination limits | API4 Unrestricted Resource Consumption | |
| Denial of service by expensive operations | API4 Unrestricted Resource Consumption | Do not test destructively on production |
| Vertical privilege escalation / admin function access | API5 Broken Function Level Authorization | Function-level, not object-level |
| Race condition / automated abuse of purchase, signup, voting flows | API6 Unrestricted Access to Sensitive Business Flows | |
| SSRF via API parameters (webhooks, URL fetchers) | API7 Server Side Request Forgery | |
| CORS misconfiguration | API8 Security Misconfiguration | |
| Verbose errors / stack traces / debug mode | API8 Security Misconfiguration | |
| Missing security headers / weak TLS | API8 Security Misconfiguration | |
| XXE | API8 Security Misconfiguration | |
| Injection (SQL, NoSQL, command, SSTI) | API8 Security Misconfiguration | The 2023 list has no dedicated injection category; map via root cause |
| Exposed old API versions / undocumented endpoints / shadow APIs | API9 Improper Inventory Management | |
| Exposed Swagger/OpenAPI/GraphQL introspection with internal endpoints | API9 Improper Inventory Management | Only when it exposes non-public functionality |
| Trusting third-party API data without validation | API10 Unsafe Consumption of APIs | |
| Insecure deserialization of upstream data | API10 Unsafe Consumption of APIs | Secondary: API8 |
| Open redirect | API8 Security Misconfiguration | Weak fit; document the reason |
| Hardcoded secrets in client apps | API8 Security Misconfiguration | |

## Table 3: Vulnerability class to OWASP Top 10 for LLM Applications 2025

| Vulnerability Class | OWASP LLM Top 10 2025 | Notes |
|---|---|---|
| Direct prompt injection / jailbreak | LLM01 Prompt Injection | |
| Indirect prompt injection via documents, web pages, tools | LLM01 Prompt Injection | |
| Leakage of PII, secrets or training data in outputs | LLM02 Sensitive Information Disclosure | |
| Compromised model, plugin, dataset or dependency | LLM03 Supply Chain | |
| Poisoned fine-tuning or retrieval data | LLM04 Data and Model Poisoning | |
| Unsanitized model output rendered or executed downstream (XSS, SQLi, SSRF, command execution via LLM output) | LLM05 Improper Output Handling | Map the downstream flaw too |
| Agent with excessive tools, permissions or autonomy | LLM06 Excessive Agency | |
| Exposure of system prompt contents | LLM07 System Prompt Leakage | Impact depends on sensitive content in the prompt |
| Cross-tenant leakage in vector stores / embedding inversion | LLM08 Vector and Embedding Weaknesses | |
| Hallucinated or misleading output relied upon | LLM09 Misinformation | |
| Unbounded token usage / cost abuse / model denial of service | LLM10 Unbounded Consumption | |
| IDOR or auth flaws in the LLM application's own API | - | Map to the Web or API tables; not LLM-specific |
| Standard web flaws in the chat front end (XSS, CSRF) | - | Map to the Web table unless caused by model output (LLM05) |

## Reporting notes
- Tag each finding with the primary category from every list that applies (web, API, LLM). Skip lists that do not apply to the target.
- For LLM findings, state whether the issue is in the model behavior, the application wrapper, or the tools the model can call, because remediation ownership differs.
- Prompt injection claims need a reproducible effect on application behavior or data (Demonstrated). Model refusing or complying in a chat alone is Inferred or Unproven.
