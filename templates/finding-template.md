# {{finding_id}} — {{title}}

> Plantilla de finding individual. Rellenar cada sección con evidencia real.
> Ningún campo puede quedar como suposición — si no hay evidencia, usar
> `N/A — no verificado` y explicar por qué, no inventar un valor.

## Severity

**CVSS 3.1 Vector:** `{{cvss_vector}}`
**CVSS 3.1 Score:** {{cvss_score}} ({{cvss_rating}})

Justificación por métrica (cada una debe trazarse a lo observado, no a lo
teóricamente posible):

| Métrica | Valor | Por qué |
|---|---|---|
| AV (Attack Vector) | {{av}} | {{av_justification}} |
| AC (Attack Complexity) | {{ac}} | {{ac_justification}} |
| PR (Privileges Required) | {{pr}} | {{pr_justification}} |
| UI (User Interaction) | {{ui}} | {{ui_justification}} |
| S (Scope) | {{scope}} | {{scope_justification}} |
| C (Confidentiality) | {{c}} | {{c_justification}} |
| I (Integrity) | {{i}} | {{i_justification}} |
| A (Availability) | {{a}} | {{a_justification}} |

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
