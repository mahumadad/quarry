# Pivot Graph — Metodología

> Mientras `chain-matrix.md` responde "¿estos dos findings combinan?" a
> nivel de par, el pivot graph responde la pregunta a nivel de engagement
> completo: "¿cuál es el camino más corto (o más viable) desde el acceso
> inicial hasta los crown jewels, usando todos los findings confirmados
> como posibles saltos?". Es el modo grafo de `engine/chain_engine.py`.

## Por qué un grafo y no solo la matriz

La matriz de chains encuentra combinaciones de a pares. Pero un ataque real
casi nunca es un solo par — es una secuencia de saltos donde cada acceso
obtenido habilita el siguiente. El pivot graph modela el engagement como un
grafo dirigido y permite preguntar: dado todo lo confirmado hasta ahora,
¿existe una ruta completa desde "sin acceso" hasta "control del activo más
valioso"? Esto expone cadenas de 3, 4 o más saltos que nunca aparecerían
mirando solo pares.

## Construcción del grafo

### Nodos

Un nodo representa un **estado de acceso/capacidad**, no un finding en sí.
Ejemplos de nodos:

- `unauthenticated` (estado inicial, siempre existe)
- `authenticated:user_basic`
- `authenticated:user_admin`
- `access:internal_network`
- `access:cloud_iam_role:{{role_name}}`
- `access:db:read_only`
- `access:db:read_write`
- `access:filesystem:{{host}}`
- `access:shell:{{host}}`
- `crown_jewel:{{asset_name}}` (nodo objetivo — definido al inicio del
  engagement junto con el cliente: qué activo representa el peor caso de
  impacto)

Un mismo engagement puede tener varios nodos de crown jewel (ej. "base de
datos de PII de clientes", "capacidad de transferir fondos", "control del
pipeline de CI/CD").

### Aristas

Una arista representa la **técnica/finding que permite moverse de un nodo
a otro**, con un peso/metadata asociado:

```
(nodo_origen) --[finding_id, técnica, confianza]--> (nodo_destino)
```

- `finding_id`: referencia al finding que habilita este salto (debe estar
  CONFIRMED o EXPLOITED — no se agregan aristas desde findings `Unproven`).
- `técnica`: descripción corta (ej. "IDOR secuencial", "SSRF a metadata
  endpoint").
- `confianza`: `demonstrated` (el salto se ejecutó realmente) o
  `theoretical` (el salto es plausible dado lo confirmado pero no se
  ejecutó end-to-end por scope/tiempo/riesgo — útil para mapear rutas
  candidatas sin inflar lo ya demostrado).

Cada arista que representa un salto que modifica estado del target o es
irreversible se marca `requires_human_gate: true`, heredado de las reglas
de `CLAUDE.md`.

### Ejemplo mínimo

```
[unauthenticated]
     | F003: password reset token predecible (demonstrated)
     v
[authenticated:user_basic]
     | F007: IDOR en /organizations, sin rate limit (demonstrated)
     v
[access:db:read_only (PII de terceros)]
     | F011: endpoint de export confía en rol declarado en JWT (demonstrated)
     v
[authenticated:user_admin]
     | F014: panel admin permite ejecutar jobs arbitrarios (theoretical — no ejecutado, fuera de ventana de testing)
     v
[crown_jewel:control_total_de_la_plataforma]
```

## Construcción práctica (pasos)

1. **Definir crown jewels con el cliente** antes de empezar el hunting —
   sin esto, el grafo no tiene destino y solo describe accesos aislados.
2. **Agregar el nodo inicial** `unauthenticated` (o el nivel de acceso
   provisto si el engagement es gray/white-box).
3. **Por cada finding CONFIRMED/EXPLOITED**, preguntar: ¿qué nodo de origen
   requiere (qué acceso necesito para ejecutar esta técnica) y a qué nodo
   de destino me lleva (qué acceso nuevo obtengo)? Agregar la arista.
4. **Recalcular tras cada finding nuevo** — el grafo se construye
   incrementalmente durante el engagement, no solo al final.
5. **Correr BFS** desde cada nodo inicial hacia cada crown jewel después de
   agregar findings nuevos (ver algoritmo abajo).
6. **Cada camino encontrado es una chain candidata** — pasa a
   `chain-report.md` y al pipeline de validación adversarial antes de
   reportarse.

## Búsqueda de caminos: BFS desde acceso inicial a crown jewels

Se usa BFS (no DFS) porque interesa encontrar primero las rutas más
**cortas** (menor número de saltos = menor complejidad de ataque = más
relevante para priorizar, consistente con la métrica AC/Attack Complexity
de CVSS) antes de explorar rutas largas y menos prácticas.

```
función buscar_rutas(grafo, nodo_inicial, crown_jewels):
    cola = [(nodo_inicial, camino=[])]
    visitados = {nodo_inicial}
    rutas_encontradas = []

    mientras cola no esté vacía:
        (nodo_actual, camino) = cola.pop(0)

        si nodo_actual está en crown_jewels:
            rutas_encontradas.append(camino)
            continuar  # seguir buscando otras rutas, no cortar el BFS

        para cada arista (nodo_actual -> nodo_siguiente) en grafo:
            si nodo_siguiente no está en visitados:
                visitados.add(nodo_siguiente)
                cola.append((nodo_siguiente, camino + [arista]))

    retornar rutas_encontradas  # ordenadas por longitud (ya lo garantiza BFS)
```

Notas de implementación para `engine/chain_engine.py`:

- No marcar un nodo como "visitado" de forma permanente si el objetivo es
  enumerar *todas* las rutas razonables (no solo la más corta) — usar
  visitados por camino (permitir revisitar un nodo por un camino distinto)
  cuando el grafo es pequeño (engagements típicos tienen decenas, no miles,
  de nodos). Para grafos grandes, limitar profundidad máxima en vez de
  desactivar visitados globalmente, para evitar explosión combinatoria.
- Priorizar en el output las rutas donde **todas** las aristas son
  `demonstrated` sobre las que incluyen algún salto `theoretical` — las
  primeras son chains ya reportables, las segundas son candidatas a validar.
- Cuando una ruta incluye una arista `requires_human_gate: true` que no se
  ejecutó todavía, la ruta se reporta como "camino viable, pendiente de
  autorización para el salto final" — nunca se asume completada.

## Lectura del grafo para priorización

- **Nodos con alto grado de salida** (habilitan muchos saltos siguientes)
  son puntos de apalancamiento — si un finding lleva a uno de estos nodos,
  vale la pena invertir tiempo extra en confirmarlo aunque su CVSS
  individual sea moderado.
- **Rutas cortas con todas las aristas `demonstrated`** son las chains que
  van primero en el Top 3 del executive summary.
- **Cuellos de botella** (un solo finding es la única arista hacia un
  crown jewel) son el punto de remediación de mayor ROI para el cliente:
  arreglar ese finding específico corta todas las rutas que dependen de él.
- **Nodos sin aristas entrantes desde `unauthenticated` ni desde ningún
  nodo alcanzable** representan superficie que quedó fuera de la cobertura
  — se cruzan con la Coverage Matrix del engagement report para confirmar
  si es un gap real o simplemente no es alcanzable dado el diseño del
  sistema.

## Representación en el reporte

En `chain-report.md`, el bloque "Pivot graph" es el sub-grafo lineal
específico de esa chain (una sola ruta). En `engagement-report.md`, se
puede incluir el grafo completo del engagement (todas las rutas conocidas)
como apéndice visual cuando el número de nodos lo justifica — para
engagements simples con 2-3 chains, suele ser más claro listar las chains
individuales que forzar una visualización de grafo completo.
