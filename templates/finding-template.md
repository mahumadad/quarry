# {{finding_id}} — {{title}}

> Plantilla de finding individual. Rellenar cada sección con evidencia real.
> Ningún campo puede quedar como suposición — si no hay evidencia, usar
> `N/A — no verificado` y explicar por qué, no inventar un valor.

## Severity

**CVSS 4.0 Vector:** `{{cvss_vector_4}}`
**CVSS 4.0 Score:** {{cvss_score}} ({{cvss_rating}})
**CVSS 3.1 Vector (si el cliente/plataforma lo exige):** `{{cvss_vector_31}}`
**EPSS:** {{epss_score}} (percentil {{epss_percentile}}, consultado {{epss_date}}) — solo si hay CVE
**CISA KEV:** {{cisa_kev}} (true/false + due-date si aplica) — solo si hay CVE

Ver `references/cvss4-epss-kev.md` para las reglas de composición. EPSS/KEV
modulan prioridad de remediación, NO el score CVSS.

Justificación por métrica (cada una debe trazarse a lo observado, no a lo
teóricamente posible):

| Métrica | Valor | Por qué |
|---|---|---|
| AV (Attack Vector) | {{av}} | {{av_justification}} |
| AC (Attack Complexity) | {{ac}} | {{ac_justification}} |
| AT (Attack Requirements) | {{at}} | {{at_justification}} (condiciones fuera del control del atacante — solo si se demostraron) |
| PR (Privileges Required) | {{pr}} | {{pr_justification}} |
| UI (User Interaction) | {{ui}} | {{ui_justification}} (N / P passive / A active) |
| VC/VI/VA (Vulnerable system) | {{vc_vi_va}} | {{vulnerable_impact_justification}} |
| SC/SI/SA (Subsequent system) | {{sc_si_sa}} | {{subsequent_impact_justification}} |

## CWE

**{{cwe_id}}** — {{cwe_name}}

## MITRE ATT&CK

| Tactic | Technique ID | Technique |
|---|---|---|
| {{tactic}} | {{technique_id}} | {{technique_name}} |

## Target Asset

- **Host/URL:** {{target_asset}}
- **Componente:** {{component}} (ej. endpoint, parámetro, servicio, header)
- **Entorno:** {{environment}} (prod / staging / dev)

## Description

{{description}}

Debe responder: qué es la vulnerabilidad, dónde vive en el flujo de la
aplicación, y qué condición la habilita (falta de validación, control de
acceso roto, configuración por defecto, etc.). No repetir el título — explicar
el mecanismo.

## Steps to Reproduce

1. {{step_1}}
2. {{step_2}}
3. {{step_3}}
4. {{step_n}}

Cada paso debe ser ejecutable por un tercero sin contexto adicional. Si un
paso requiere una herramienta, nombrarla con la versión/flags exactos usados.

## Evidence

### Request

```http
{{request_raw}}
```

### Response

```http
{{response_raw}}
```

### Evidencia adicional

- Screenshot: {{screenshot_path}} (si aplica — DOM change, alert, archivo descargado)
- Output de herramienta: {{tool_output_path}}
- Timestamp de la prueba: {{test_timestamp}}

**Evidence tag:** `{{evidence_tag}}` — Demonstrated / Inferred / Unproven
(ver `references/anti-fabrication-rules.md`; un finding con tag `Unproven`
no se reporta como vulnerabilidad confirmada, se documenta como hipótesis
abierta en Gaps del engagement report).

## Impact (Demonstrated)

{{impact_demonstrated}}

Describir únicamente lo que se demostró en esta prueba (datos extraídos,
acceso obtenido, acción ejecutada). No extrapolar a "un atacante podría..."
sin evidencia de ese paso siguiente — si la cadena continúa, documentarla
como chain aparte en `chain-report.md`.

## Remediation

{{remediation}}

- **Fix inmediato:** {{remediation_immediate}}
- **Fix estructural:** {{remediation_structural}}
- **Prioridad sugerida:** {{remediation_priority}} (justificada por severity + explotabilidad, no solo por CVSS score)

## Detection Opportunities (engagements contratados, no bounty)

> Ver `skills/report/detection-opportunities`. Un bloque corto; si no se
> conoce el stack defensivo del cliente, escribir tool-agnostic y marcar la
> implementación como client-specific. Nunca afirmar "no hay detección" sin
> haber visto la telemetría del cliente.

- **Data sources (ATT&CK):** {{detection_data_sources}}
- **Telemetría esperada:** {{detection_expected_telemetry}} (qué sistema, qué campos, qué umbral/firma)
- **Observado:** {{detection_observed}} (fired / not fired / no verificado — con nota)
- **Idea de detección:** {{detection_idea}} (regla/consulta concreta o lógica tool-agnostic)
- **Replay test:** {{detection_replay}} (Atomic Red Team test ID por técnica, o pasos mínimos de replay)

## References

- {{reference_1}}
- {{reference_2}}
- {{reference_cwe_link}}
- {{reference_mitre_link}}

---

**Finding status:** {{status}} (DETECTED → CONFIRMED → EXPLOITED → CHAINED → VALIDATED → REPORTED)
**Descubierto por:** {{discovered_by}}
**Fecha:** {{date}}
**Chains relacionadas:** {{chain_refs}}
**Custodia:** evidencia registrada en custody log (eventos: {{custody_event_ids}})
