---
name: pt:status
description: Dashboard del engagement — fase, findings, cobertura, budget, gaps, próximos pasos
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:status

Lee todo el estado persistido del engagement activo y lo presenta como
un dashboard de una sola pantalla. No modifica nada — es un comando de
solo lectura. Útil al retomar una sesión, después de una compactación de
contexto, o simplemente para orientarse.

## Precondición

- Debe existir `.pentest-state/engagement.json`. Si no existe, decirlo
  claramente y recomendar `/pt:engage <target>` — no inventar un estado
  vacío con apariencia de dashboard.

## Pasos exactos

1. Cargar `EngagementState` → fase actual, target, fecha de creación,
   historial de transiciones de fase.
2. Cargar `Scope` → conteo de entradas in-scope/out-of-scope (no el
   detalle completo, eso es trabajo de `/pt:scope --show`).
3. Cargar `FindingsStore.summary()` → total, desglose por status
   (detected/confirmed/exploited/chained/validated/reported/killed) y
   por severidad.
4. Cargar `ChainEngine.list_chains()` → conteo total y por status
   (candidate/verified/killed).
5. Cargar `CoverageTracker.summary()` → assets cubiertos, vuln_classes
   totales, ratio de cobertura, celdas con finding, celdas skipped.
6. Cargar `BudgetManager.summary()` → uso por fase (used/limit/remaining),
   resaltar cualquier fase ≥80% de uso.
7. Cargar `RebuttalEngine.summary()` si hay sesiones → conteo por
   outcome (pending/accepted/stall/killed/exhausted). Resaltar sesiones
   `pending` — son trabajo de validación sin terminar.
8. Calcular gaps de cobertura (`CoverageTracker.get_gaps()`) y mostrar
   los 10 más relevantes (priorizar assets con findings ya detectados en
   otras clases — ahí es más probable que haya más).
9. Derivar la(s) próxima(s) acción(es) recomendada(s) según la fase y el
   estado (tabla de abajo).

## Lógica de "próxima acción recomendada"

| Situación observada | Recomendación |
|---|---|
| Fase `INIT` o sin engagement | `/pt:engage <target>` |
| Fase `SCOPED`, sin recon | `/pt:recon` |
| Fase `RECON`, sin mapas | `/pt:map` |
| Fase `MAPPED`/`HUNTING`, cobertura <100% y budget de hunting <80% | `/pt:hunt` sobre los gaps listados |
| ≥2 findings `CONFIRMED`/`EXPLOITED` sin cadenas analizadas | `/pt:chain` |
| Findings `DETECTED`/`CONFIRMED` acumulados sin pasar pipeline | `/pt:validate` |
| Findings `VALIDATED` sin reportar | `/pt:report` |
| Budget de alguna fase ≥80% | Escalar al operador antes de seguir — no recomendar más tool calls en esa fase sin decisión humana |
| Sesiones de rebuttal en `pending` | Completar esas sesiones antes de abrir trabajo nuevo |

Si aplican varias filas a la vez, listarlas todas en orden de urgencia
(budget crítico y rebuttals pendientes primero, luego avance de fase).

## Edge cases

- **Archivos de estado parcialmente corruptos o ausentes** (ej.
  `findings.json` no existe pero `engagement.json` sí — engagement
  recién creado): tratar como "0 findings", no como error, salvo que el
  JSON exista y esté malformado — en ese caso sí reportarlo como
  problema de estado a investigar, no silenciarlo.
- **Fase y contenido inconsistentes** (ej. fase `REPORTING` pero 0
  findings `VALIDATED`): señalar la inconsistencia explícitamente en el
  dashboard, no solo mostrar los números por separado.
- **Engagement muy viejo sin actividad reciente** (`updated_at` lejano):
  mencionarlo — puede ser relevante para decidir si el scope/autorización
  sigue vigente antes de retomar.

## Output esperado

Dashboard de una pantalla, en este orden:
1. Target, engagement ID, fase actual, última actividad.
2. Scope: conteo in/out-of-scope, referencia de autorización presente
   sí/no.
3. Findings: total y desglose por status y severidad.
4. Chains: total y por status.
5. Cobertura: ratio, assets, celdas con finding, top gaps.
6. Budget: uso por fase, alertas ≥80%.
7. Rebuttal: sesiones pendientes si las hay.
8. Run actual: `run_id`, estados por tarea, gates, interrumpidas y siguiente
   acción de `Orchestrator.resume_plan()`.
9. Integridad: resultado de `Orchestrator.doctor()` para artefactos y custodia.
10. Próximas acciones recomendadas (lista priorizada, de la tabla anterior).
