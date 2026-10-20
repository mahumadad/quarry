# Chain Report — {{chain_id}}

> Una chain documenta cómo dos o más findings individuales, combinados,
> producen un impacto mayor a la suma de sus partes. Un finding entra en
> una chain solo si está en estado CONFIRMED o EXPLOITED — no se encadenan
> hipótesis.

**Chain ID:** {{chain_id}}
**Nombre descriptivo:** {{chain_name}}
**Fecha:** {{date}}
**Analista:** {{analyst}}

## Findings involucrados

| Finding ID | Título | Rol en la cadena | Status |
|---|---|---|---|
| {{finding_id_1}} | {{finding_title_1}} | {{role_1}} (ej. acceso inicial) | {{status_1}} |
| {{finding_id_2}} | {{finding_title_2}} | {{role_2}} (ej. habilita el salto) | {{status_2}} |
| {{finding_id_n}} | {{finding_title_n}} | {{role_n}} (ej. impacto final) | {{status_n}} |

## Chain description

{{chain_description}}

Explicar en una o dos frases qué capacidad otorga cada finding y por qué
esa capacidad es precisamente lo que el siguiente finding necesita para
avanzar. Ver `references/chains/chain-patterns.md` si la combinación
coincide con un patrón conocido — citarlo por nombre.

**Patrón de chain matrix aplicable:** {{matrix_pattern_ref}} (o "ad-hoc" si no coincide con ningún patrón catalogado)

## Combined CVSS

**Vector combinado:** `{{combined_cvss_vector}}`
**Score combinado:** {{combined_cvss_score}} ({{combined_cvss_rating}})

| Finding | CVSS individual |
|---|---|
| {{finding_id_1}} | {{individual_cvss_1}} |
| {{finding_id_2}} | {{individual_cvss_2}} |

**Justificación del combinado:** {{combined_cvss_justification}} — el score
combinado debe reflejar el impacto end-to-end demostrado (ej. S:C si la
cadena cruza un trust boundary que ningún finding individual cruzaba solo),
no un promedio ni la suma de los individuales.

## Attack narrative (paso a paso)

1. **{{narrative_step_1_title}}** — {{narrative_step_1_detail}}
   - Finding usado: {{finding_id_1}}
   - Resultado: {{narrative_step_1_result}}
2. **{{narrative_step_2_title}}** — {{narrative_step_2_detail}}
   - Finding usado: {{finding_id_2}}
   - Resultado: {{narrative_step_2_result}}
3. **{{narrative_step_n_title}}** — {{narrative_step_n_detail}}
   - Finding usado: {{finding_id_n}}
   - Resultado final: {{narrative_step_n_result}}

Cada paso debe incluir la evidencia (o referencia a la evidencia del finding
individual) que demuestra que ese salto específico ocurrió, no solo que es
plausible.

## Combined impact

{{combined_impact}}

Describir el impacto de negocio de la cadena completa (ej. "dump completo
del padrón de usuarios con PII" en vez de "IDOR + falta de rate limit").
Indicar si el impacto fue demostrado en su totalidad o si el último salto
se infiere por evidencia parcial (en ese caso, marcar explícitamente qué
parte quedó como `Inferred`).

## Pivot graph (representación textual)

```
[{{node_initial}}]
     | {{edge_1_technique}} (finding: {{finding_id_1}})
     v
[{{node_intermediate_1}}]
     | {{edge_2_technique}} (finding: {{finding_id_2}})
     v
[{{node_intermediate_n}}]
     | {{edge_n_technique}} (finding: {{finding_id_n}})
     v
[{{node_final}}]  <-- crown jewel / impacto final
```

Ver `references/chains/pivot-graph.md` para la metodología completa de
construcción del grafo a nivel de engagement (este bloque es el sub-grafo
específico de esta chain).

---

**Chain status:** {{chain_status}} (CANDIDATE → VALIDATED → REPORTED)
**Requiere gate humano antes de ejecutar el último salto:** {{requires_human_gate}} (sí/no — cualquier salto que modifique estado del target o sea irreversible requiere confirmación explícita antes de ejecutarse, aunque la chain completa ya esté aprobada en concepto)
