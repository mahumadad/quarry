# Executive Summary — {{engagement_name}}

**Cliente:** {{client_name}}
**Período del engagement:** {{start_date}} – {{end_date}}
**Audiencia:** Dirección / no técnica

---

## Engagement overview

{{engagement_overview}}

En 2-3 frases: qué se evaluó (producto/sistema), con qué objetivo, y qué
metodología general se usó (ej. "caja gris, simulando un atacante con
cuenta de usuario básico"). Sin jerga técnica innecesaria.

## Key metrics

| Severidad | Cantidad |
|---|---|
| Critical | {{count_critical}} |
| High | {{count_high}} |
| Medium | {{count_medium}} |
| Low | {{count_low}} |
| Informational | {{count_info}} |
| **Total findings** | **{{count_total}}** |
| **Chains identificadas** | **{{count_chains}}** |

**Cobertura del engagement:** {{coverage_percentage}}% de la superficie en
scope fue evaluada activamente (ver Gaps en el reporte completo para el
detalle de lo no cubierto).

## Top 3 critical chains

> No es lo mismo el finding más severo que la cadena de mayor riesgo real.
> Estas tres son las que combinan mayor probabilidad de explotación con
> mayor impacto de negocio.

1. **{{chain_1_name}}** — {{chain_1_one_line_impact}}
   (Findings: {{chain_1_finding_ids}})
2. **{{chain_2_name}}** — {{chain_2_one_line_impact}}
   (Findings: {{chain_2_finding_ids}})
3. **{{chain_3_name}}** — {{chain_3_one_line_impact}}
   (Findings: {{chain_3_finding_ids}})

## Risk rating

**Postura de riesgo general: {{overall_risk_rating}}**

{{risk_rating_justification}}

Justificar en una frase: por qué esa calificación (ej. "Crítica, porque
existe una cadena demostrada de toma de cuenta sin interacción del usuario
víctima, explotable de forma remota y sin autenticación previa").

## Immediate actions required

Acciones que deberían iniciarse antes de que termine la lectura de este
documento — no es la lista completa de recomendaciones (esa va en el reporte
completo), es lo urgente.

1. {{immediate_action_1}}
2. {{immediate_action_2}}
3. {{immediate_action_3}}

---

*Este resumen es una síntesis del reporte técnico completo
(`engagement-report.md`). Ante cualquier discrepancia, el reporte completo
es la fuente de verdad.*

**Preparado por:** {{report_author}}
**Fecha:** {{report_date}}
