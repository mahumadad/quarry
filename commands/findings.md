---
name: pt:findings
description: Lista findings con filtros por status, clase y opcionalmente su análisis de cadenas
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:findings [--status <status>] [--class <class>] [--chains]

Lista findings del engagement activo, con filtros combinables. Comando
de solo lectura — no modifica `findings.json` ni `chains.json`.

## Precondición

- Debe existir `.pentest-state/findings.json`. Si no existe o está
  vacío, decirlo ("0 findings registrados") y sugerir `/pt:hunt` — no es
  un error, puede ser simplemente el estado temprano del engagement.

## Argumentos

- `--status <status>` — uno de `detected`, `confirmed`, `exploited`,
  `chained`, `validated`, `reported`, `killed` (valores de
  `FindingStatus`). Si el valor no matchea ninguno, listar los válidos y
  pedir que se repita.
- `--class <class>` — uno de los 38 `ALL_VULN_CLASSES` de
  `engine/coverage.py`, o el nombre de skill `hunt-*` (normalizar antes
  de comparar). Si no matchea, listar valores cercanos (coincidencia
  parcial) antes de fallar.
- `--chains` — además de la lista, para cada finding mostrado, resolver
  y mostrar sus `chain_refs` y cualquier `Chain` de `chains.json` donde
  aparezca su ID en `findings[]`.
- Sin argumentos: listar todos, sin filtrar, ordenados por severidad
  (critical → info) y dentro de cada severidad por status (más avanzado
  primero: reported → validated → ... → detected → killed al final).

## Pasos exactos

1. Cargar `FindingsStore` completo.
2. Aplicar filtros en orden: `--status` primero (usar
   `FindingsStore.list_by_status`), luego `--class` sobre ese subconjunto
   (usar `FindingsStore.list_by_class`, o filtrar manualmente si ambos
   filtros se combinan).
3. Si `--chains`: cargar `ChainEngine`, y para cada finding filtrado,
   `chain.get_chain(ref)` por cada ID en `finding.chain_refs`, más una
   búsqueda directa en `list_chains()` por si el finding aparece en una
   cadena sin que `chain_refs` se haya actualizado todavía (no asumir
   que `chain_refs` siempre está sincronizado — es responsabilidad de
   `/pt:chain` y `/pt:validate` mantenerlo, pero verificar aquí de todas
   formas).
4. Renderizar tabla.

## Formato de tabla (sin `--chains`)

| ID | Título | Severidad | Status | Evidence tag | Asset |
|---|---|---|---|---|---|

## Formato con `--chains`

Igual que arriba, más por cada finding con cadenas asociadas, una
sub-lista indentada:
```
F-A1B2C3D4  IDOR en /api/orders/:id  high  confirmed  inferred  api.target.com
  └─ C-9F8E7D6C: idor + rate-limiting → mass-data-exfiltration (critical, candidate)
```

## Edge cases

- **Filtro combinado sin resultados** (ej. `--status killed --class
  ssrf` y no hay ninguno): decirlo explícitamente ("0 findings con esos
  filtros"), no mostrar tabla vacía sin contexto — y sugerir correr sin
  `--class` para ver si el status existe en otras clases.
- **Finding con `chain_refs` apuntando a un ID que ya no existe en
  `chains.json`** (ej. una cadena se fusionó/depuró en `/pt:validate`):
  señalarlo como referencia rota en vez de omitirlo silenciosamente —
  es una señal de que el estado necesita limpieza.
- **Muchos findings (>30)**: paginar o agrupar por severidad con
  conteos, y preguntar si se quiere el detalle completo o solo el
  resumen agregado — no volcar una tabla gigante sin que se pida.
- **`--class` que matchea una skill que cubre varias vuln_classes**
  (ej. `--class xss` debería incluir `xss-reflected`, `xss-dom` y
  `xss-stored`): expandir el filtro a las 3, no solo a una coincidencia
  exacta de string.

## Output esperado

- Tabla filtrada con el conteo total al inicio ("14 findings, filtrado a
  5").
- Si `--chains`: sub-listas de cadenas por finding, como arriba.
- Un resumen de 1 línea al final: cuántos de los listados están en cada
  status, para contexto rápido sin tener que contar filas.
