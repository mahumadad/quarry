---
name: pt:resume
description: Reanuda un engagement sin repetir ni perder tareas tras una interrupción
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:resume [run_id]

1. Cargar `.pentest-state/engagement.json`, scope, autorización y ventana.
   Si cualquiera falta, está corrupto o expiró, detenerse fail-closed.
2. Ejecutar `Orchestrator.doctor()` y mostrar problemas de integridad antes de
   continuar. Una cadena rota o evidencia alterada exige revisión humana.
3. Seleccionar el run indicado o el más reciente. Ejecutar
   `recover_interrupted(run_id)`: toda tarea que quedó `running` pasa a
   `interrupted`, nunca a completada.
4. Presentar `resume_plan`: fase, siguiente tarea, intentos, fallos recientes,
   artefactos disponibles y gates pendientes.
5. Reanudar con `/pt:run --resume <run_id>` solamente después de verificar los
   artefactos de tareas interrumpidas. Si su resultado quedó persistido y es
   íntegro, registrarlo; si no, repetir de forma idempotente esa tarea.
6. No saltar tareas solo porque su skill aparece en un checkpoint antiguo:
   `runs.json` y `journal.jsonl` son la fuente autoritativa.
