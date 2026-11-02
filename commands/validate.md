---
name: quarry:validate
description: Pipeline de validación de findings — higiene de evidencia, dedup, 4 gates, 7-Question Gate, rebuttal adversarial
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:validate [finding_id|--all]

Corre el pipeline completo de validación sobre un finding específico o
sobre todos los pendientes de validar. Nada se reporta (`/quarry:report`) sin
haber pasado por este pipeline — es el control anti-fabricación del
plugin hecho proceso, no solo regla en `CLAUDE.md`.

## Argumento

- `<finding_id>` (ej. `F-A1B2C3D4`) — valida solo ese finding (o cadena,
  si el ID empieza con `C-`).
- `--all` — valida todos los findings en status `DETECTED`, `CONFIRMED`
  o `EXPLOITED`, y todas las cadenas en status `candidate`. Sin
  argumento, pedir cuál de los dos modos se quiere — no asumir `--all`
  por defecto, porque correr rebuttal contra todo puede ser costoso en
  tool calls (ver `budget.py`).

## Las 5 etapas, en orden estricto

No saltar etapas aunque el finding "se vea obviamente válido" — el orden
existe porque cada etapa depende de que la anterior ya limpió el
terreno.

### 1. Higiene de evidencia (`skills/validate/evidence-hygiene`)

Verificar por cada finding/cadena:
- ¿La evidencia es reproducible (request/response completo, o output de
  herramienta con timestamp)? Si falta, **no avanzar** — volver a
  `/quarry:hunt` para esa celda y capturar evidencia real primero.
- ¿La evidencia demuestra el impacto reclamado, o solo una precondición?
  (ej. "se ve el parámetro reflejado" no es lo mismo que "el XSS
  ejecuta").
- ¿Están los targets anonimizados donde corresponda guardar para
  reutilización futura, sin perder la evidencia real en el engagement
  actual?

Findings que fallan higiene → quedan en `DETECTED` con nota de qué
evidencia falta. No pasan a la siguiente etapa.

### 2. Deduplicación (`skills/validate/dedup`)

Para el set que pasó higiene:
- Agrupar findings que comparten la misma causa raíz aunque tengan
  síntomas distintos (ej. mismo endpoint sin output encoding, reflejado
  en 3 parámetros distintos).
- Fusionar duplicados en un único finding con múltiples
  `steps_to_reproduce`, manteniendo el ID más antiguo y marcando los
  otros como `KILLED` con `reason="duplicate of F-XXXXXXXX"`.
- Para cadenas: verificar que no sean la misma cadena vista desde dos
  pares de findings distintos.

### 3. Los 4 gates (`skills/validate/finding-validation`)

Cada finding debe pasar los 4, explícitamente, documentando la respuesta:

1. **Refutation** — ¿hay una razón válida para matar este finding?
   Recorrer las `REFUTATION_QUESTIONS` de `engine/rebuttal.py` (¿es
   reproducible por alguien sin contexto previo?, ¿un WAF/rate-limiter/
   CSRF token ya lo bloquea?, ¿el PoC demuestra el impacto o solo una
   precondición?, ¿es observación informativa y no vulnerabilidad?,
   ¿podría ser falso positivo de scanner?, ¿la severidad está inflada
   respecto a lo demostrado?, ¿un atacante real lo explotaría o es
   teórico?, ¿el endpoint es alcanzable desde una posición externa/no
   privilegiada?, ¿hay supuestos de deployment que no se sostienen en
   producción?, ¿ya se chequeó dedup?).
2. **Reachability** — ¿el endpoint/función vulnerable es alcanzable
   dentro del scope autorizado, sin requerir acceso que el atacante
   modelado no tendría?
3. **Trigger** — ¿existe un disparador concreto y repetible (request,
   comando, secuencia de acciones) que active la vulnerabilidad, no solo
   una condición teórica?
4. **Impact** — ¿el impacto reclamado está demostrado (Demonstrated) o
   es inferido/asumido? Si es `Inferred` o `Unproven`, la severidad
   reportada no puede exceder lo que esa evidencia realmente sostiene.

Un finding que falla cualquiera de los 4 gates no avanza — se devuelve a
`DETECTED`/`CONFIRMED` con la razón específica, o se mata si el gate
muestra que es inválido.

### 4. 7-Question Gate (triage, `skills/validate/triage-gate`)

Checklist de triage final antes del rebuttal adversarial — 7 preguntas
que cualquier revisor externo haría primero. Si `skills/validate/
triage-gate/SKILL.md` no está escrito aún, usar como base las 7
preguntas estándar de triage de bug bounty (duplicado conocido, dentro
de scope del programa/cliente, severidad consistente con impacto real,
PoC completo y reproducible, no requiere ingeniería social no
autorizada, no es un "best practice" sin impacto demostrable, afecta a
una versión/configuración realmente desplegada) y señalarlo como gap de
contenido.

### 5. Rebuttal adversarial (`engine/rebuttal.py`)

Para cada finding que llegó hasta aquí:
1. `RebuttalEngine.start_session(finding_id, max_rounds=3)`.
2. Generar el prompt del checker con `get_checker_prompt(...)` — **el
   checker actúa ciego**: no debe recibir el razonamiento del operador
   ni el contexto del engagement, solo el finding y su evidencia en
   JSON. Si estás ejecutando ambos roles en la misma sesión, simula
   genuinamente la postura adversarial — no valides tu propio trabajo
   con una objeción de cortesía.
3. El generador (rol validador, con contexto completo) responde al
   challenge del checker.
4. Registrar la ronda con `record_round(finding_id, challenge, response,
   outcome)`, donde `outcome` es `ACCEPTED`, `STALL` o `KILLED`.
5. Repetir hasta `ACCEPTED`/`KILLED`, o hasta 3 rondas (`EXHAUSTED`).
6. Mapear el resultado final al finding:
   - `ACCEPTED` → `FindingsStore.update_status(id, FindingStatus.VALIDATED)`,
     `rebuttal_result="ACCEPTED"`.
   - `KILLED` → `update_status(id, FindingStatus.KILLED, reason=...)`.
   - `STALL`/`EXHAUSTED` → el finding queda sin avanzar; se reporta al
     operador como "necesita más evidencia", nunca se infla a
     `VALIDATED` por cansancio del loop.

## Edge cases

- **Finding ya `VALIDATED` o `REPORTED`**: no reprocesar salvo que el
  operador pida re-validación explícita (ej. apareció nueva evidencia
  que lo contradice).
- **Cadena (`C-XXXXXXXX`) en vez de finding**: el pipeline aplica igual,
  pero el "finding" evaluado es la combinación — el checker debe
  intentar refutar específicamente que la combinación produce más
  impacto que cada parte por separado, no solo refutar cada parte.
- **`--all` con volumen alto**: antes de arrancar, mostrar cuántos
  findings/cadenas entrarán al pipeline y el costo estimado en tool
  calls; si supera el budget disponible de la fase `validating`
  (`BudgetManager.get_tracker("validating")`), confirmar con el operador
  antes de proceder o sugerir priorizar por severidad.
- **STALL repetido en la misma categoría de finding**: si varios
  findings de la misma clase quedan en STALL por el mismo motivo (ej.
  "falta evidencia de impacto real" en varios XSS), señalarlo como
  patrón — probablemente la metodología de esa skill de hunt necesita
  ajuste, no solo cada finding individual.

## Output esperado

Tabla final por finding/cadena: ID, título, etapa donde terminó
(higiene/dedup/gates/triage/rebuttal), resultado (`ACCEPTED`/`STALL`/
`KILLED`), y razón en una línea. Resumen agregado
(`FindingsStore.summary()` + `RebuttalEngine.summary()`).

Próximo paso recomendado: `/quarry:report` si hay findings `VALIDATED`;
si todo quedó en `STALL`, volver a `/quarry:hunt`/`/quarry:chain` por evidencia
adicional antes de reintentar validación.
