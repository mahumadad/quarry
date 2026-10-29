---
name: pt:doctor
description: Audita integridad, tareas huérfanas, artefactos y referencias del engagement
allowed-tools: Bash(*), Read(*)
---

# /pt:doctor

Ejecuta `python3 -m engine.orchestrator doctor --audit-dir <audit_dir>` y
revisa además que todos los JSON de `.pentest-state` sean parseables.

Reportar por separado: estado corrupto, tareas `running` huérfanas, tareas
completadas sin timestamp, artefactos ausentes/alterados, custodia rota,
findings sin evidencia, outputs declarados ausentes y secretos fuera del vault.
Incluir capacidades `tool_unavailable` del registry, wordlists cuyo SHA-256/tamaño cambió y
estadísticas de memoria. La retención de `memory_maintenance.py` es explícita y archiva antes de
podar; doctor no borra memoria ni evidencia por cuenta propia.
No reparar ni sobrescribir automáticamente evidencia o estado corrupto.
