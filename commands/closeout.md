---
name: pt:closeout
description: Close engagement with final coverage summary and deliverable checklist
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:closeout — Cierre formal del engagement

Uso: `/pt:closeout`

Lanza `workflows/closeout.yaml`. La regla: un engagement NO está terminado
cuando se entrega el reporte — está terminado cuando el closeout se completa.

## Checklist que ejecuta

1. **Limpieza de artefactos** — todo archivo subido, cuenta creada, webhook
   configurado y cambio de estado deliberado queda removido, delegado al
   cliente, o documentado como irreversible. Sin excepciones.
2. **Higiene de credenciales** — vault rotado/revocado, tokens del
   engagement muertos, ninguna credencial fuera del vault.
3. **Sello de evidencia** — `CustodyLog.verify()` final (debe estar ÍNTEGRA),
   evento de cierre, y bundle con manifest SHA-256 vía `/pt:deliver`.
4. **Retención de datos** — destino contractual de los datos del engagement;
   la destrucción se registra en custody como último evento. `knowledge.py`
   solo conserva técnicas anonimizadas — verificar.
5. **Debrief** — sesión de cierre con el cliente (walkthrough de críticos,
   gaps, próximos pasos: retest / surface-watch / purple-team).

## Reglas

- Cada ítem de limpieza exige evidencia de remoción (request que confirma
  404, cuenta deshabilitada, etc.) — "yo lo borré" no es verificación.
- Si un artefacto NO puede removerse (dato escrito sin rollback), queda en
  el reporte como tal — el cliente debe saberlo.
- El closeout también tiene ventana: correrlo dentro del tiempo autorizado
  (timeguard), porque la limpieza misma toca el target.
