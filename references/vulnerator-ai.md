# Vulnerator-AI — Referencia

> Agente autónomo de pentesting basado en OODA loop.
> Repo: github.com/irraz/vulnerator-ai (MIT, 90+ stars)
> Usado como referencia de diseño, no como dependencia.

## Qué es

Agente OODA (Observe→Orient→Decide→Act) que ejecuta tools en un
contenedor Kali vía MCP. 4 contenedores: kali (tools), playwright-mcp
(browser), ooda-agent (Hermes/Mistral Large 4), vulnerator-mcp (run
lifecycle).

## Ideas adoptadas para el plugin

### 1. Finding schema estructurado (JSONL)

Cada finding es un JSON con campos tipados:

```json
{
  "id": "uuid",
  "title": "...",
  "state": "hypothesis|partial|confirmed|discarded",
  "phase": "observe|orient|decide|act",
  "technique_id": "T1078",
  "target": "host:port/path",
  "evidence": {
    "command": "curl exacto re-ejecutable",
    "output": "respuesta verbatim",
    "returncode": 0
  },
  "confidence": "high|medium|low",
  "recorded_at": "ISO8601"
}
```

**Mapeo a nuestro sistema:**
- `hypothesis` → nuestro `Unproven`
- `partial` → nuestro `Inferred`
- `confirmed` → nuestro `Demonstrated`
- `discarded` → no tiene equivalente directo, agregar a custody log

### 2. Scope guard como JSON (allow/deny CIDR + hosts)

```json
{
  "enabled": true,
  "allow": [
    {"cidr": "10.0.0.0/24"},
    {"host": "target.example.com"}
  ],
  "deny": [
    {"cidr": "10.0.0.1/32"}
  ],
  "ports": [80, 443, 8080]
}
```

Nuestro `engine/scope.py` puede adoptar este formato para scope
machine-readable además del scope textual actual.

### 3. Niveles de explotación L1-L4

| Nivel | Nombre | Equivale a |
|---|---|---|
| L1 | Identificado | Patrón detectado, sin cambio de comportamiento |
| L2 | Parcial | Sink alcanzado, defensa en medio |
| L3 | Confirmado | Payload cambia comportamiento observable |
| L4 | Crítico | Datos extraídos, código ejecutado, acceso escalado |

Complementa nuestro Demonstrated/Inferred/Unproven con granularidad
en la fase de explotación.

### 4. Reglas de disciplina web

- "No exploit, no report" — sin prueba no hay finding confirmado
- "Agota bypasses antes de descartar" — un payload bloqueado no es
  visto bueno hasta probar bypasses razonables
- "Un informe no es un PASS" — solo "sin hallazgos explotables
  encontrados en el alcance X con los métodos Y"
- Evidencia cruda y re-ejecutable, no resúmenes
- Scripts incrustados en heredoc, no en /tmp efímero

### 5. Delegación con contexto fresco

Ramas de exploración largas (barrido de /24, fuzzing extenso) se
delegan a subagentes con contexto limpio. El conductor recibe solo el
resumen. Ya lo hacemos con forks, pero la disciplina de "no delegues
la decisión OODA, solo la recolección" es valiosa.

## Qué NO adoptamos

- **Sin gates de scope** — vulnerator-ai delega scope al operador sin
  enforcement mecánico. Nosotros sí lo enforceamos en scope.py.
- **Ephemeral state** — su estado por engagement es deliberadamente
  efímero. Nuestro custody.py es append-only y hash-chained.
- **Sin human gates** — no tiene gates para explotación. Nosotros sí
  (CLAUDE.md, guard.py).
- **Modelo local** — usa Hermes/Mistral. Nosotros usamos Claude como
  conductor.

## Arquitectura (referencia)

```
┌─────────────┐    ┌──────────────┐    ┌────────────────┐
│ ooda-agent  │───▶│  kali-mcp    │───▶│  kali container│
│ (Hermes)    │    │  :8900       │    │  (nmap, nuclei,│
│             │    └──────────────┘    │   sqlmap, etc.) │
│             │    ┌──────────────┐    └────────────────┘
│             │───▶│ playwright   │
│             │    │ MCP :8931    │
└─────────────┘    └──────────────┘
```
