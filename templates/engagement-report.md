# Engagement Report — {{engagement_name}}

**Cliente:** {{client_name}}
**Fecha de inicio:** {{start_date}}
**Fecha de cierre:** {{end_date}}
**Tipo de engagement:** {{engagement_type}} (web app / API / cloud / AD / mobile / red team)
**Equipo:** {{team_members}}
**Clasificación del documento:** {{classification}} (ej. Confidencial — solo cliente)

---

## Executive Summary

{{executive_summary}}

Ver también `executive-summary.md` para la versión de una página destinada
a audiencia no técnica. Esta sección debe ser consistente con esa, pero con
más detalle: qué se probó, qué se encontró, cuál es el riesgo real (no el
conteo de findings), y qué debería pasar primero.

**Postura de riesgo general:** {{overall_risk_posture}} (ej. Crítica / Alta / Media / Baja)

## Scope

### In scope

| Asset | Tipo | Notas |
|---|---|---|
| {{scope_asset_1}} | {{scope_type_1}} | {{scope_notes_1}} |
| {{scope_asset_2}} | {{scope_type_2}} | {{scope_notes_2}} |

### Out of scope

| Asset | Razón de exclusión |
|---|---|
| {{oos_asset_1}} | {{oos_reason_1}} |

### Reglas de engagement

- **Ventana de testing:** {{testing_window}}
- **Técnicas excluidas:** {{excluded_techniques}} (ej. DoS volumétrico, phishing a empleados sin autorización separada)
- **Contacto de emergencia:** {{emergency_contact}}
- **Autorización:** {{authorization_reference}} (documento/email que autoriza el engagement)

## Methodology

{{methodology_summary}}

Fases ejecutadas: {{phases_executed}} (recon → mapping → hunting → chaining →
validación adversarial → reporting). Para cada fase, referenciar qué
cobertura se logró — el detalle fino va en la Coverage Matrix más abajo.

**Herramientas utilizadas:** {{tools_used}}

## Target Card

{{target_card_embed_or_ref}}

Insertar aquí la target card completa (ver `target-card.md`) del target
principal, o un link/referencia si el engagement cubrió múltiples targets
con cards separadas.

## Findings (ordenados por severidad)

| ID | Título | CVSS | Severity | Status | CWE |
|---|---|---|---|---|---|
| {{finding_id_1}} | {{finding_title_1}} | {{cvss_1}} | Critical | {{status_1}} | {{cwe_1}} |
| {{finding_id_2}} | {{finding_title_2}} | {{cvss_2}} | High | {{status_2}} | {{cwe_2}} |
| {{finding_id_n}} | {{finding_title_n}} | {{cvss_n}} | {{severity_n}} | {{status_n}} | {{cwe_n}} |

Cada finding referenciado acá tiene su reporte completo en formato
`finding-template.md` en el Appendix o en archivo separado.

## Chains

| Chain ID | Findings combinados | Impacto combinado | CVSS combinado |
|---|---|---|---|
| {{chain_id_1}} | {{chain_findings_1}} | {{chain_impact_1}} | {{chain_cvss_1}} |
| {{chain_id_2}} | {{chain_findings_2}} | {{chain_impact_2}} | {{chain_cvss_2}} |

Cada chain referenciada tiene su reporte completo en formato
`chain-report.md`.

## Coverage Matrix

Matriz vuln_class × asset — qué se probó explícitamente, qué dio resultado,
y qué quedó sin probar (y por qué).

| Vuln class | {{asset_1}} | {{asset_2}} | {{asset_n}} |
|---|---|---|---|
| SQLi | {{coverage_sqli_asset1}} | {{coverage_sqli_asset2}} | {{coverage_sqli_assetn}} |
| XSS | {{coverage_xss_asset1}} | {{coverage_xss_asset2}} | {{coverage_xss_assetn}} |
| SSRF | {{coverage_ssrf_asset1}} | {{coverage_ssrf_asset2}} | {{coverage_ssrf_assetn}} |
| IDOR/BAC | {{coverage_idor_asset1}} | {{coverage_idor_asset2}} | {{coverage_idor_assetn}} |
| Auth bypass | {{coverage_auth_asset1}} | {{coverage_auth_asset2}} | {{coverage_auth_assetn}} |
| ... | ... | ... | ... |

Convención de celda: `Tested — Clean`, `Tested — Finding(s): {{ids}}`,
`Not tested — {{razón}}`, `N/A — {{razón}}`.

## Gaps

{{gaps_summary}}

Listar explícitamente qué NO se probó, y por qué: fuera de scope, falta de
tiempo, requería credenciales no provistas, requería acción destructiva sin
autorización separada, etc. Esta sección es tan importante como los
findings — un gap no reportado es un falso sentido de seguridad para el
cliente.

| Gap | Razón | Riesgo residual estimado |
|---|---|---|
| {{gap_1}} | {{gap_reason_1}} | {{gap_risk_1}} |
| {{gap_2}} | {{gap_reason_2}} | {{gap_risk_2}} |

## Recommendations

Priorizadas por reducción de riesgo real, no solo por CVSS score individual
(una chain de severidad media que es trivial de explotar puede priorizarse
sobre un finding crítico que requiere condiciones improbables).

1. **{{recommendation_1}}** — aborda: {{recommendation_1_findings}}
2. **{{recommendation_2}}** — aborda: {{recommendation_2_findings}}
3. **{{recommendation_3}}** — aborda: {{recommendation_3_findings}}

### Recomendaciones estructurales (más allá de los findings puntuales)

{{structural_recommendations}}

## MITRE ATT&CK Heatmap

Técnicas observadas durante el engagement, mapeadas a tactics.

| Tactic | Técnicas observadas |
|---|---|
| Reconnaissance | {{tactic_recon_techniques}} |
| Initial Access | {{tactic_initial_access_techniques}} |
| Execution | {{tactic_execution_techniques}} |
| Persistence | {{tactic_persistence_techniques}} |
| Privilege Escalation | {{tactic_privesc_techniques}} |
| Defense Evasion | {{tactic_evasion_techniques}} |
| Credential Access | {{tactic_credaccess_techniques}} |
| Discovery | {{tactic_discovery_techniques}} |
| Lateral Movement | {{tactic_lateral_techniques}} |
| Collection | {{tactic_collection_techniques}} |
| Exfiltration | {{tactic_exfil_techniques}} |
| Impact | {{tactic_impact_techniques}} |

## Appendix (raw evidence)

- {{appendix_item_1}} — {{appendix_item_1_path}}
- {{appendix_item_2}} — {{appendix_item_2_path}}

Incluir: outputs crudos de herramientas (nmap -oX, nuclei -json, etc.),
capturas de tráfico relevantes, listados completos de endpoints
descubiertos, logs de la sesión de testing con timestamps.

---

**Documento preparado por:** {{report_author}}
**Fecha del reporte:** {{report_date}}
**Versión:** {{report_version}}
