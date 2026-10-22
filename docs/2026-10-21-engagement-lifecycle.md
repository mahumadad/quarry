# Engagement Lifecycle — 2026-10-21 (segunda parte)

> Continuación de `2026-10-21-depth-layers.md`. Aquellas eran capas de
> profundidad técnica; estas cubren el ciclo de vida completo del engagement
> como SERVICIO profesional — lo que pasa antes, durante (fuera del hunting)
> y después del reporte.

## Piezas agregadas

| Pieza | Tipo | Problema que resuelve |
|-------|------|----------------------|
| `engine/timeguard.py` | engine | Las ROE definen ventanas de testing; nada impedía tráfico ofensivo a las 3am. Guard mecánico: ventanas por día/hora, expiración del engagement, override solo si la ROE lo permite. Fail-open si no hay config (con aviso), fail-closed si la hay. |
| `engine/deliver.py` | engine | El entregable debe ser exactamente lo attestado. Manifest SHA-256 por archivo + bundle tar.gz + cifrado gpg opcional. Alteración post-entrega detectable. |
| `workflows/closeout.yaml` + `/pt:closeout` + `templates/closeout-checklist.md` | workflow | El pecado clásico: webshell de prueba olvidado, cuentas de test vivas, datos del cliente sin destino. Limpieza verificada (con evidencia de remoción), rotación de credenciales, sello final de custodia, retención/destrucción registrada, debrief. |
| `commands/notify.md` + `templates/critical-alert.md` | protocolo | Un RCE en prod el martes no espera al reporte del viernes. Escalación el mismo día por canal de emergencia, congelamiento de la línea de ataque, registro en custody. También cubre: evidencia de compromiso previo del cliente (posible incidente activo). |
| `workflows/cve-response.yaml` | workflow | Cae un CVE que afecta el stack del cliente → validación quirúrgica (aplicabilidad → exposición → PoC dirigido → nota corta), no engagement completo. La respuesta negativa documentada también es un entregable. |
| `workflows/surface-watch.yaml` | workflow | Monitoreo continuo entre engagements: recon pasivo + diff contra baseline (target_diff), alerta solo si hay cambios. Diseñado para cron. |
| `workflows/purple-team.yaml` | workflow | Sesión en vivo con el SOC: replay de PoCs observando su SIEM, ciclo detect→tune→verify. Convierte la tabla Detection Coverage de estimada a observada. |
| `skills/report/report-qc` | skill | QC adversarial del DOCUMENTO (no de las vulns): claim→evidencia, consistencia interna (summary == tabla == store), auditoría never-submit final, honestidad de cobertura, cadena ÍNTEGRA antes de entregar. FAIL bloquea la entrega. |

## El ciclo de vida completo resultante

```
engage → [timeguard activo durante TODO] → recon → mapping → hunting
  → chaining → validation → report → report-qc → deliver (manifest+gpg)
  → [notify en cualquier momento si hay crítico]
  → closeout (cleanup + seal + debrief)
  → retest (post-fix) / cve-response (nuevo CVE) / surface-watch (continuo)
  → purple-team (con el SOC)
```

Cada transición deja evento en custody — el engagement completo es
attestable de punta a punta.
