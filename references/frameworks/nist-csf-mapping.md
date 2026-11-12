# NIST CSF 2.0 Mapping for Common Pentest Findings

Map findings to NIST Cybersecurity Framework 2.0 so remediation can be tied to a governance outcome.

## How to use this table
- CSF 2.0 has six Functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC).
- Map to the control outcome that failed, not to the vulnerability name. A technical flaw usually lands in Protect; the missing detection or process that let it persist maps to Detect, Identify or Govern.
- A finding can have a primary mapping and an optional secondary one. Keep to one or two.
- Subcategory IDs follow the CSF 2.0 numbering (for example PR.AA-05). Verify wording against the official CSF 2.0 document (https://www.nist.gov/cyberframework) before delivery, because subcategory text is paraphrased below.
- This mapping does not affect severity or evidence level.

## Category reference

| Function | Category | Meaning |
|---|---|---|
| Govern | GV.OC | Organizational Context |
| Govern | GV.RM | Risk Management Strategy |
| Govern | GV.RR | Roles, Responsibilities, and Authorities |
| Govern | GV.PO | Policy |
| Govern | GV.OV | Oversight |
| Govern | GV.SC | Cybersecurity Supply Chain Risk Management |
| Identify | ID.AM | Asset Management |
| Identify | ID.RA | Risk Assessment |
| Identify | ID.IM | Improvement |
| Protect | PR.AA | Identity Management, Authentication, and Access Control |
| Protect | PR.AT | Awareness and Training |
| Protect | PR.DS | Data Security |
| Protect | PR.PS | Platform Security |
| Protect | PR.IR | Technology Infrastructure Resilience |
| Detect | DE.CM | Continuous Monitoring |
| Detect | DE.AE | Adverse Event Analysis |
| Respond | RS.MA | Incident Management |
| Respond | RS.AN | Incident Analysis |
| Respond | RS.CO | Incident Response Reporting and Communication |
| Respond | RS.MI | Incident Mitigation |
| Recover | RC.RP | Incident Recovery Plan Execution |
| Recover | RC.CO | Incident Recovery Communication |

## Application and API findings

| Finding Type | CSF Function | Category | Subcategory |
|---|---|---|---|
| SQL injection / injection flaws | Protect | PR.PS | PR.PS-06 Secure software development practices are integrated and their performance monitored |
| Command injection / RCE | Protect | PR.PS | PR.PS-06 Secure software development practices |
| SSTI / insecure deserialization / XXE | Protect | PR.PS | PR.PS-06 Secure software development practices |
| Cross-site scripting (XSS) | Protect | PR.PS | PR.PS-06 Secure software development practices |
| CSRF / missing anti-forgery controls | Protect | PR.PS | PR.PS-06 Secure software development practices |
| SSRF | Protect | PR.IR | PR.IR-01 Networks and environments are protected from unauthorized logical access and usage |
| IDOR / BOLA / broken object-level authorization | Protect | PR.AA | PR.AA-05 Access permissions, entitlements, and authorizations are defined and managed (least privilege, separation of duties) |
| Broken function-level authorization / privilege escalation | Protect | PR.AA | PR.AA-05 Access permissions and authorizations (least privilege) |
| Mass assignment / excessive data exposure | Protect | PR.DS | PR.DS-01 Confidentiality, integrity and availability of data-at-rest are protected |
| Insecure file upload | Protect | PR.PS | PR.PS-05 Installation and execution of unauthorized software are prevented |
| Path traversal / local file inclusion | Protect | PR.PS | PR.PS-06 Secure software development practices |
| Business logic flaw / race condition | Protect | PR.PS | PR.PS-06 Secure software development practices |
| Open redirect | Protect | PR.PS | PR.PS-06 Secure software development practices |
| CORS misconfiguration | Protect | PR.PS | PR.PS-01 Configuration management practices are established and applied |
| Missing security headers / insecure defaults | Protect | PR.PS | PR.PS-01 Configuration management practices |
| Clickjacking | Protect | PR.PS | PR.PS-01 Configuration management practices |

## Authentication and access findings

| Finding Type | CSF Function | Category | Subcategory |
|---|---|---|---|
| Authentication bypass | Protect | PR.AA | PR.AA-03 Users, services, and hardware are authenticated |
| Weak password policy / default credentials | Protect | PR.AA | PR.AA-01 Identities and credentials for authorized users, services, and hardware are managed |
| Missing multi-factor authentication | Protect | PR.AA | PR.AA-03 Users, services, and hardware are authenticated (commensurate with risk) |
| No rate limiting / lockout on login | Protect | PR.AA | PR.AA-03 Users, services, and hardware are authenticated |
| Session management flaws / session fixation | Protect | PR.AA | PR.AA-04 Identity assertions are protected, conveyed, and verified |
| JWT / token validation flaws | Protect | PR.AA | PR.AA-04 Identity assertions are protected, conveyed, and verified |
| OAuth / SSO misconfiguration | Protect | PR.AA | PR.AA-04 Identity assertions are protected, conveyed, and verified |
| Excessive privileges / stale accounts | Protect | PR.AA | PR.AA-05 Access permissions and authorizations (least privilege) |
| User enumeration | Protect | PR.AA | PR.AA-03 Users, services, and hardware are authenticated |

## Data, configuration and infrastructure findings

| Finding Type | CSF Function | Category | Subcategory |
|---|---|---|---|
| Hardcoded secrets / credentials in code or repos | Protect | PR.AA | PR.AA-01 Identities and credentials are managed |
| Sensitive data exposure at rest (PII, backups, buckets) | Protect | PR.DS | PR.DS-01 Data-at-rest is protected |
| Weak TLS / cleartext transport | Protect | PR.DS | PR.DS-02 Data-in-transit is protected |
| Information disclosure (verbose errors, debug endpoints) | Protect | PR.PS | PR.PS-01 Configuration management practices |
| Exposed admin interfaces / management ports | Protect | PR.IR | PR.IR-01 Networks and environments are protected from unauthorized logical access |
| Network segmentation weaknesses | Protect | PR.IR | PR.IR-01 Networks and environments are protected from unauthorized logical access |
| Publicly readable cloud storage | Protect | PR.DS | PR.DS-01 Data-at-rest is protected |
| Unpatched / outdated software and components | Protect | PR.PS | PR.PS-02 Software is maintained, replaced, and removed commensurate with risk |
| Vulnerable third-party dependency | Govern | GV.SC | GV.SC-07 Risks posed by a supplier and their products are understood, recorded, prioritized, assessed, responded to, and monitored |
| Missing SPF / DKIM / DMARC | Protect | PR.PS | PR.PS-01 Configuration management practices |
| Denial of service / unrestricted resource consumption | Protect | PR.IR | PR.IR-04 Adequate resource capacity to ensure availability is maintained |
| Missing backups or untested restoration | Protect | PR.DS | PR.DS-11 Backups of data are created, protected, maintained, and tested |

## Visibility, process and governance findings

| Finding Type | CSF Function | Category | Subcategory |
|---|---|---|---|
| Insufficient logging of security events | Protect | PR.PS | PR.PS-04 Log records are generated and made available for continuous monitoring |
| No monitoring / alerting on attack activity | Detect | DE.CM | DE.CM-01 Networks and network services are monitored to find potentially adverse events |
| Application activity not monitored | Detect | DE.CM | DE.CM-09 Computing hardware and software, runtime environments, and their data are monitored |
| Attacks not analyzed or correlated | Detect | DE.AE | DE.AE-02 Potentially adverse events are analyzed to better understand associated activities |
| Shadow IT / unknown internet-facing assets | Identify | ID.AM | ID.AM-02 Inventories of software, services, and systems are maintained |
| Subdomain takeover / dangling DNS | Identify | ID.AM | ID.AM-02 Inventories of software, services, and systems are maintained |
| Vulnerabilities not identified or tracked | Identify | ID.RA | ID.RA-01 Vulnerabilities in assets are identified, validated, and recorded |
| No vulnerability disclosure policy / security.txt | Identify | ID.RA | ID.RA-08 Processes for receiving, analyzing, and responding to vulnerability disclosures are established |
| Findings recur across assessments | Identify | ID.IM | ID.IM-02 Improvements are identified from security tests and exercises |
| No incident response plan or untested plan | Respond | RS.MA | RS.MA-01 The incident response plan is executed in coordination with relevant third parties once an incident is declared |
| Slow containment capability | Respond | RS.MI | RS.MI-01 Incidents are contained |
| No recovery plan or restoration process | Recover | RC.RP | RC.RP-01 The recovery portion of the incident response plan is executed once initiated |
| No security policy or ownership for the affected system | Govern | GV.PO | GV.PO-01 Policy for managing cybersecurity risks is established based on organizational context and strategy |
| Unclear security roles and accountability | Govern | GV.RR | GV.RR-02 Roles, responsibilities, and authorities related to cybersecurity risk management are established |
| Third-party / supplier risk not managed | Govern | GV.SC | GV.SC-07 Supplier risks are understood, recorded, prioritized, assessed, responded to, and monitored |

## Reporting notes
- Use the Protect row to describe the control that failed, and add a Detect or Identify row only when the engagement evidence shows the gap (for example, attack traffic produced no alert).
- Do not claim a Govern gap from a single technical finding. Govern mappings need evidence of a policy, ownership or supplier-management failure.
