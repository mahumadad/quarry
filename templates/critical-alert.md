# ALERTA CRÍTICA — {{engagement_name}}

> Alerta de hallazgo crítico DURANTE el engagement. Se envía el mismo día
> del descubrimiento por el canal de emergencia acordado. No es el reporte —
> es lo mínimo para que el cliente actúe ya.

**Para:** {{emergency_contact}}
**Fecha/hora:** {{alert_timestamp}}
**De:** {{operator}}
**Severidad:** {{severity}} (CVSS 4.0: {{cvss_score}})

## Veredicto (una línea)

{{verdict}}

## Qué encontramos

{{summary}}

- **Asset afectado:** {{affected_asset}}
- **Estado:** Confirmado (evidencia disponible bajo solicitud — no adjunta
  en esta alerta por sensibilidad)
- **Explotación activa observada:** {{active_exploitation}} (sí/no/desconocido)

## Lo que pedimos AHORA

1. {{immediate_action_1}} (ej. deshabilitar endpoint X, rotar credencial Y)
2. {{immediate_action_2}}

## Lo que NO vamos a tocar

{{frozen_scope}} — congelamos esta línea de ataque hasta su confirmación,
para no amplificar impacto en producción.

## Notas

- El engagement continúa por otras líneas salvo que indiquen lo contrario.
- El detalle técnico completo (PoC, evidencia, remediación estructural) va
  en el reporte del engagement — ID de finding: {{finding_id}}.
- Registrado en la cadena de custodia del engagement: {{custody_event}}.
