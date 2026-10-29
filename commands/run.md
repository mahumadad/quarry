---
name: pt:run
description: Crea o continua una corrida determinística y auditable de un workflow
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:run [workflow] [--resume <run_id>]

Usa `engine/orchestrator.py` como única entrada de ejecución. El workflow por
defecto es `workflows/full-pentest.yaml`; no ejecutar fases por memoria ni
construir una segunda secuencia desde `router.py`.

1. Verificar engagement, scope, autorización y ventana vigente.
2. Ejecutar el preflight de `ToolRegistry`: persistir capacidades sin backend y versiones elegidas;
   seleccionar listas mediante `WordlistIndex` cuando la tarea las use. No instalar herramientas
   ni descargar listas implícitamente.
3. Sin `--resume`: crear la corrida con el workflow elegido y las celdas de
   cobertura descubiertas. Guardar y mostrar su `run_id`.
4. Con `--resume`: cargar ese run, recuperar tareas `running` como
   `interrupted`, revisar sus artefactos y continuar solo desde la primera
   tarea pendiente o interrumpida.
5. Antes de cada tarea, cargar `Orchestrator.briefing()`. Ejecutar la skill
   indicada, conservar primero los artefactos crudos y después devolver uno de
   estos estados: `completed`, `skipped`, `failed` o `blocked`, con razón.
6. Un gate humano bloquea la corrida. Reanudar únicamente tras aprobación del
   operador mediante `approve_gate`; nunca aprobar en nombre del operador.
7. No convertir timeout, output truncado, herramienta ausente o excepción en
   `tested_clean`. Esos casos son `failed`, `blocked`, `tool_unavailable` o `inconclusive`.
8. Antes de validar/reportar, aplicar convergencia de self/program duplicates y enlazar IDs o
   referencias; no repetir el pipeline para una redetección del mismo root cause.
9. Al finalizar, mostrar estados, gaps, artefactos y custodia. La corrida solo
   termina realmente después de QC, entrega y closeout.

Toda acción de red debe usar `ProtectedHTTPClient` o `ToolRunner`; no crear
requests paralelos que eviten la política común.
