---
name: quarry:chain
description: Analiza combinaciones de findings — matriz pairwise, grafo de pivoteo, o ambos. El comando clave del plugin.
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:chain [--matrix|--graph|--full]

Este es el comando diferenciador del plugin (`engine/chain_engine.py`).
Un pentest manual típico reporta findings aislados; este comando busca
sistemáticamente qué combinaciones de findings menores producen impacto
crítico combinado, y qué rutas de pivoteo existen desde acceso inicial
hasta los crown jewels definidos en la target card.

Por defecto, sin argumento, corre `--full` (matrix + graph).

## Precondición

- Debe haber al menos 2 findings con status `CONFIRMED`, `EXPLOITED` o
  `CHAINED` (`FindingsStore.list_chainable()`). Si hay 0 o 1, informar
  que no hay material para encadenar y sugerir `/quarry:hunt` primero — no
  es un error, es un estado normal temprano en el engagement.
- Leer los 5 mapas de `/quarry:map` si existen — el capability map en
  particular define qué cuenta como "crown jewel" para el modo grafo.

## Modo matriz (`--matrix`)

Análisis combinatorio pairwise sobre todos los findings chainable:

1. Cargar findings con `FindingsStore.list_chainable()`.
2. Ejecutar `ChainEngine.analyze_matrix(findings)` — internamente:
   - Compara cada par `(F_i, F_j)` contra `KNOWN_CHAINS` (patrones
     conocidos: IDOR+no-rate-limit→mass-exfil, XSS-stored+CSRF→ATO,
     SSRF+cloud-metadata→credential-theft, etc. — ver
     `references/chains/chain-matrix.md` para el catálogo completo, y
     plus any operator-specific patterns from prior engagements).
   - También expande `ENABLES_MAP` (qué clase habilita la explotación
     de cuál otra, más allá de pares catalogados exactos).
   - Deduplica candidatos por `(findings frozenset, name)`.
3. Cada `Chain` candidata queda persistida en `chains.json` con
   `status="candidate"` y `evidence_tag="inferred"` — **una cadena
   candidata NO es un hallazgo validado**. Es una hipótesis estructural
   que debe pasar por `/quarry:validate` antes de reportarse.
4. Para cada candidata con severidad `critical` o `high`, intentar
   verificar manualmente la combinación (encadenar los dos PoCs en la
   práctica) antes de pasarla a validación — si la combinación no
   reproduce en la práctica (ej. el rate-limit sí corta después de N
   requests, más alto de lo esperado pero no infinito), bajar su
   severidad o marcarla `killed` con la razón.

## Modo grafo (`--graph`)

Construye el grafo de pivoteo y busca rutas hacia los crown jewels:

1. `ChainEngine.build_pivot_graph(findings, assets)` — nodos = assets +
   capacidades obtenidas (`"<asset>:<capability>"` via `ENABLES_MAP`),
   aristas = findings que habilitan el salto.
2. Identificar el/los nodo(s) de "acceso inicial" (el primer finding
   explotable sin credenciales, o el primer punto de entrada del
   capability map).
3. Identificar las keywords de "crown jewel" desde la target card
   (pregunta 2) y el capability map — ej. `["admin", "database",
   "payment", "pii"]`.
4. `ChainEngine.find_paths(graph, start=<acceso_inicial>, goal_keywords=[...])`
   — BFS que devuelve hasta 50 rutas. Si hay 0 rutas, no es un fallo del
   comando: significa que con los findings actuales no hay un camino
   conocido hasta los crown jewels, y eso es información válida para el
   reporte (gap, no éxito ni fracaso).
5. Priorizar las rutas más cortas (menos findings encadenados = cadena
   más práctica de ejecutar y más creíble para el cliente).

## Pasos exactos (modo `--full`, default)

1. Correr modo matriz completo.
2. Correr modo grafo completo.
3. Cruzar resultados: toda cadena del modo grafo que coincida con una
   candidata del modo matriz se marca como doblemente confirmada
   (mayor confianza).
4. Escribir `<audit_dir>/report/chains.md` (Write tool) usando
   `templates/chain-report.md` si existe, si no con esta estructura por
   cadena: nombre, findings involucrados (IDs + 1 línea cada uno),
   descripción del mecanismo, impacto combinado, severidad combinada,
   evidence_tag, y — si aplica — el path completo del grafo.
5. No transicionar automáticamente findings individuales a `CHAINED` —
   eso requiere que la cadena específica pase el gate humano y
   `/quarry:validate`. Aquí solo se registran como `chain_refs` candidatos.

## Edge cases

- **Findings de severidad baja que combinados dan critical**: estos son
  exactamente el objetivo del comando — no descartarlos por severidad
  individual baja. Reportarlos con el mismo detalle que las cadenas
  "obvias".
- **Dos findings con la misma causa raíz** (no deduplicados todavía):
  el modo matriz puede generar una "cadena" espuria entre dos síntomas
  del mismo bug. Señalar la sospecha de duplicado en el output y
  recomendar `/quarry:validate --all` (paso dedup) antes de confiar en esa
  cadena.
- **Grafo sin acceso inicial claro** (todos los findings requieren
  autenticación previa): documentar esto explícitamente — es una señal
  de que falta un finding de autenticación/bypass para que el kill
  chain completo sea viable, útil para dirigir el siguiente `/quarry:hunt`.
- **Cadena que cruza fuera del scope original** (ej. el pivote llega a
  un asset no autorizado): detener esa rama de la cadena en el límite
  de scope, documentar hasta dónde llega dentro de lo autorizado, y
  reportar al operador que ahí hay una ruta de pivoteo no verificable
  sin ampliar scope — nunca verificarla sin autorización nueva.

## Output esperado

- Lista de cadenas candidatas (matriz) con severidad combinada, ordenadas
  de mayor a menor impacto.
- Rutas del grafo de pivoteo desde acceso inicial a crown jewels (si las
  hay), con longitud de cada ruta.
- Ruta de `chains.md`.
- Próximo paso recomendado: `/quarry:validate` sobre las cadenas y findings
  candidatos antes de reportar nada como confirmado.
