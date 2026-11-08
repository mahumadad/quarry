---
name: quarry:vectors
description: Consulta providers alternativos para identificar vectores de ataque no explorados
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:vectors [--provider <name>] [--type <brainstorm|opinion|cve>]

Consulta un LLM alternativo (DeepSeek, GLM, Kimi, OpenRouter, Ollama)
para obtener una second opinion sobre qué vectores de ataque quedan por
explorar en el engagement actual.

## Precondición

- Engagement activo (`.pentest-state/engagement.json` existe).
- Al menos un provider configurado en `.pentest-state/providers.json`.
  Si no hay providers, guiar al operador para configurar uno:

  ```json
  {
    "providers": {
      "deepseek": {"api_key": "sk-...", "default_model": "deepseek-chat"}
    },
    "routing": {
      "vector_brainstorm": "deepseek",
      "fallback": "deepseek"
    }
  }
  ```

## Flujo

### 1. Cargar estado del engagement

Leer del Brain:
- `brain.capabilities` — qué puede hacer el atacante ahora
- `brain.exhausted_vectors` — qué se intentó y falló
- `brain.active_vectors` — qué está en progreso

Leer de `decision_engine.py`:
- Stack detectado (AppProfile)
- Skills ya ejecutadas

Leer de `findings.json`:
- Resumen de findings por clase y severidad
- Findings con tag `Inferred` que podrían beneficiarse de validación

Leer de `coverage.json`:
- Gaps de cobertura (celdas no probadas)

### 2. Construir prompt contextualizado

Usar `LLMGateway.vector_brainstorm()` que envía:
- Stack tecnológico
- Vectores exhaustos
- Capabilities ganadas
- Resumen de findings

El prompt pide vectores NO intentados, priorizados por probabilidad
de éxito. Formato: JSON array con `vector`, `target`, `rationale`,
`priority`, `vuln_class`.

### 3. Parsear respuesta y registrar leads

Cada vector sugerido se registra como Lead en `engine/leads.py`:
- `source`: `"llm_gateway:{provider}:{model}"`
- `priority`: la que sugiere el provider
- `status`: `open`
- `vuln_class_hint`: la clase sugerida

### 4. Filtrar duplicados

Antes de registrar, verificar contra:
- Leads ya existentes (por título similar)
- Exhausted vectors del Brain (ya se intentó)
- Coverage cells ya marcadas `tested_clean`

### 5. Presentar al operador

Mostrar tabla con los vectores sugeridos, indicando:
- Cuáles son nuevos (no en exhausted ni en leads)
- Cuáles confirman gaps del coverage tracker
- Cuáles el operador debería priorizar

No ejecutar nada automáticamente — solo registrar leads y recomendar.

## Subcomandos

### `/quarry:vectors --type opinion --finding <id>`

Pide una second opinion sobre un finding específico usando
`LLMGateway.second_opinion()`. Útil para findings `Inferred` donde
se quiere validación externa del assessment.

### `/quarry:vectors --type cve --service <name> --version <ver>`

Deep-dive de CVEs para un servicio usando
`LLMGateway.cve_deepdive()`. Útil cuando se detecta una versión
y se quiere saber qué CVEs aplican antes de intentar explotación.

### `/quarry:vectors --provider <name>`

Fuerza un provider específico en vez del routing configurado.

## Anti-fabricación

- Los vectores sugeridos por el LLM son **leads, no findings**.
- No se registran como findings hasta que sean verificados.
- El source tag `llm_gateway:*` deja claro el origen.
- La redaction bidireccional (`redact_for_provider`) se aplica
  ANTES de enviar al provider — no se filtran tokens, cookies,
  ni IPs reales del target.
