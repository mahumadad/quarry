---
name: pt:report
description: Genera el reporte del engagement — completo o solo resumen ejecutivo, en Markdown o PDF
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:report [--format md|pdf] [--executive]

Genera el reporte final del engagement a partir de findings `VALIDATED`
y cadenas verificadas. Por defecto: formato `md`, reporte completo (no
solo ejecutivo).

## Precondición

- Debe haber al menos 1 finding en status `VALIDATED` o `REPORTED`
  (`FindingsStore.list_by_status(FindingStatus.VALIDATED)`). Si no hay
  ninguno, detener y señalar que falta `/pt:validate` — un reporte sin
  findings validados es, en el mejor caso, un reporte de recon/cobertura,
  no un reporte de hallazgos. Ofrecer generar igual un reporte de
  "estado del engagement" si eso es lo que el operador quiere, pero no
  llamarlo reporte de findings.
- Findings en `STALL`, `DETECTED` o `CONFIRMED` (no validados) **no
  entran al reporte** como hallazgos confirmados. Si el operador insiste
  en incluirlos, deben aparecer en una sección separada y claramente
  etiquetada "no validados / en progreso", nunca mezclados con la lista
  principal.

## Argumentos

- `--format md` (default) — Markdown en `<audit_dir>/report/`.
- `--format pdf` — generar el Markdown primero igual, después convertir.
  Si hay una skill de PDF disponible en el entorno (ver skills
  disponibles: `anthropic-skills:pdf` / Adobe PDF tools), usarla para la
  conversión en vez de reinventar generación de PDF a mano.
- `--executive` — solo el resumen ejecutivo (`executive-summary.md`),
  sin el detalle técnico completo de cada finding. Pensado para
  stakeholders no técnicos.

## Secciones del reporte completo

Usar `templates/engagement-report.md` si existe; si no, esta estructura
(y señalar el gap de contenido):

1. **Resumen ejecutivo** — 1 página: qué se probó, cuántos findings por
   severidad, las 1-3 cadenas más críticas en lenguaje no técnico, y la
   recomendación principal. Esta sección es la misma que produce
   `--executive` por sí sola.
2. **Alcance y metodología** — scope confirmado (de `scope.json`),
   ventana del engagement, fases ejecutadas, limitaciones conocidas
   (ej. "no se probó fuerza bruta de credenciales por regla del
   engagement").
3. **Findings, ordenados por severidad** (critical → high → medium →
   low → info), cada uno con:
   - ID, título, clase (CWE), asset afectado
   - Severidad + CVSS 3.1 vector string, con cada métrica justificada
     por lo verificado (no copiar un vector genérico de la clase)
   - Descripción y root cause
   - Steps to reproduce, numerados
   - Evidencia (referenciar o embeber el request/response, con datos
     sensibles redactados si el reporte va a circular más allá del
     contacto autorizado)
   - Impacto demostrado (nunca "podría permitir" sin PoC)
   - Remediación concreta
   - Mapeo MITRE ATT&CK (tactic + technique ID)
   - `evidence_tag` (Demonstrated/Inferred/Unproven) visible
4. **Cadenas de ataque** — cada cadena de `/pt:chain` que pasó
   `/pt:validate`, con el mecanismo completo, los findings componentes
   (como referencia, no repetidos en extenso), e impacto combinado.
5. **Matriz de cobertura** — de `CoverageTracker.summary()` y
   `get_gaps()`: qué se probó, qué no, y por qué (scope, tiempo, o
   limitación técnica). Esto es tan importante como los findings — un
   reporte sin gaps declarados implica cobertura total, que casi nunca
   es cierta.
6. **Mapeo de frameworks** — tabla CVSS por finding, tabla MITRE ATT&CK
   agregada (qué tactics/techniques cubre el engagement en conjunto), y
   si aplica, NIST CSF / OWASP Top 10 (`references/frameworks/`).
7. **Recomendaciones** — priorizadas por severidad e impacto de negocio,
   no solo por CVSS numérico (una `medium` que habilita una cadena
   crítica se prioriza sobre una `high` aislada).
8. **Apéndices** — findings `KILLED` durante validación (con razón, para
   transparencia si el cliente pregunta por qué algo reportado por un
   scanner no aparece), y el historial de fases del engagement.

## Pasos exactos

1. Cargar findings `VALIDATED`/`REPORTED` y cadenas verificadas.
2. Si `--executive`: generar solo la sección 1, expandida a ~1-2
   páginas, y detenerse ahí.
3. Si no: generar todas las secciones en orden, escribir
   `<audit_dir>/report/engagement-report.md`.
4. Transicionar cada finding incluido de `VALIDATED` a `REPORTED`
   (`FindingsStore.update_status(id, FindingStatus.REPORTED)`).
5. Si `--format pdf`: convertir el Markdown a PDF (vía skill de PDF
   disponible), guardar junto al `.md`.
6. Transicionar la fase del engagement a `REPORTING` si venía de
   `VALIDATING`.
7. Preguntar al operador si el engagement se cierra (`Phase.CLOSED`)
   tras entregar el reporte, o si queda abierto para una ronda de
   retest — no cerrar automáticamente.

## Edge cases

- **Mezcla de findings y findings-no-validados que el operador quiere
  mostrar igual**: permitir, pero en apéndice separado y con una nota
  explícita de que no pasaron el pipeline de validación completo.
- **Cadena validada cuyos findings componentes individuales NO están
  validados** (pasó por rebuttal la combinación, pero algún finding base
  quedó en `STALL`): esto no debería ocurrir si `/pt:validate` se corrió
  correctamente sobre la cadena; si ocurre, señalarlo como inconsistencia
  de estado y resolver antes de incluir la cadena en el reporte.
- **Reporte parcial a mitad de engagement** (operador pide un snapshot
  antes de terminar hunting): generar igual, pero titularlo claramente
  "Reporte parcial — engagement en curso" y listar qué fases faltan.
- **Datos sensibles reales en evidencia** (PII, credenciales reales):
  redactar en el reporte salvo que el destinatario sea exactamente el
  contacto autorizado y el formato de entrega ya contemplado en las
  reglas del engagement.

## Output esperado

- Ruta(s) del/los archivo(s) generado(s).
- Conteo de findings incluidos por severidad, y conteo de cadenas.
- Resumen de cobertura y gaps declarados.
- Si quedaron findings `STALL`/`KILLED` relevantes, mencionarlos aunque
  no estén en el cuerpo principal del reporte.
