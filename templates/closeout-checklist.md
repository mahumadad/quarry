# Closeout Checklist — {{engagement_name}}

> Ver `workflows/closeout.yaml` y `/quarry:closeout`. Un engagement termina
> cuando esta checklist está completa, no cuando se entrega el reporte.

## 1. Limpieza de artefactos

| Artefacto | Tipo | Acción | Evidencia de remoción | Estado |
|---|---|---|---|---|
| {{artifact_1}} | upload / cuenta / webhook / cambio-estado | removido / cliente-remueve / irreversible | {{evidence_1}} | {{status_1}} |

Regla: "yo lo borré" no es evidencia — adjuntar el request que confirma la
ausencia (404, login rechazado, webhook eliminado).

## 2. Higiene de credenciales

- [ ] Credenciales de test rotadas o deshabilitadas
- [ ] Tokens API del engagement revocados
- [ ] Ninguna credencial fuera del vault (grep al directorio del engagement)

## 3. Sello de evidencia

- [ ] `CustodyLog.verify()` → ÍNTEGRO (hash cabeza: `{{custody_head}}`)
- [ ] Evento de cierre registrado en custody
- [ ] Bundle generado con manifest SHA-256 (`/quarry:deliver`)
- [ ] Bundle verificado contra su manifest

## 4. Retención / destrucción de datos

- **Acuerdo contractual:** {{retention_terms}}
- **Acción ejecutada:** {{retention_action}} (retener hasta {{date}} / destruido el {{date}})
- [ ] Destrucción registrada en custody (último evento del engagement)
- [ ] `knowledge.py` contiene solo técnicas anonimizadas — sin identificadores del cliente

## 5. Debrief

- **Fecha:** {{debrief_date}}  **Asistentes:** {{debrief_attendees}}
- [ ] Walkthrough de críticos/altos realizado
- [ ] Gaps de cobertura revisados con el cliente
- [ ] Próximos pasos acordados: {{next_steps}} (retest / surface-watch / purple-team)

---
**Closeout completado por:** {{operator}}  **Fecha:** {{closeout_date}}
