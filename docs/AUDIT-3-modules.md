# Auditoría y entrega — chain_exploit / defense_evasion / mcp_supply_chain

**Estado del sandbox:** los tres módulos que describiste no estaban en el
workspace (verifiqué filesystem, git status, untracked files y conteo de
tests: 526, no 633). Este paquete contiene una **implementación nueva** de
los tres módulos según tu especificación, construida con el mismo rigor de
la ronda anterior de auditoría. Si tu implementación real aparece, súbela:
los criterios de auditoría de este documento aplican directamente y hago
el diff.

**Suite: 648/648 verde** (526 previos + 122 tests nuevos: 32 chain_exploit,
47 defense_evasion, 43 mcp_supply_chain).

---

## 1. engine/chain_exploit.py — orquestador de cadenas multi-paso

### Diseño
- **FINDING_ORACLES**: tabla por clase de vulnerabilidad que declara
  `produces` / `consumes` (tipos de capability: `credential:*`,
  `network_access:<zone>`, `internal_service`, `code_exec`, `data_store`,
  `admin_session`, `file_read/write`, `identity`), el **oráculo**
  observable que prueba el paso (http_response para SSRF,
  credential_format para metadata leaks con patrones AKIA…/BEGIN PRIVATE
  KEY, canary command output para RCE, cross-user owner field para IDOR,
  before/after role diff para privesc) y las `evidence_keys` a registrar.
- Dos tipos de transición, ambos fail-closed en `_build_chain`:
  - **data-flow**: B consume una capability que A produjo.
  - **pivot**: el camino transporta acceso de red y B explota una
    superficie NUEVA (los consumes de B son pre-condiciones opcionales,
    no inputs transportados).
- Solo se emiten cadenas que alcanzan una GOAL capability
  (`credential:cloud_key`, `code_exec`, `data_store`, `admin_session`).
- Severidad combinada NO es el máximo de las partes: cloud cred / RCE →
  critical; admin_session + data_store → critical; cualquiera solo → high.
- `render_chain_runbook()`: instrucciones por paso con oráculo, inputs
  disponibles y evidence keys; los oráculos de ejecución de comandos
  exigen canary por intento. **El motor no ejecuta acciones de red** —
  ejecución = operador/agente bajo policy.
- `confirm_step()` con oráculo: todos los pasos confirmados → chain
  `confirmed`; cualquier fallo → `killed` (no se reporta).
- Persistencia JSONL append-only con **upsert por id** y preservación de
  líneas corruptas (nunca se pierden datos); integración al grafo con
  nodos `chain` + aristas `chains_to` a findings, confianza
  hypothesized → demonstrated según confirmación.
- Tácticas ATT&CK para la narrativa (TA0001/0006/0007/0008/0009/0010).

### Defectos que encontré y corregí durante el desarrollo (auditoría propia)
1. **Explosión combinatoria** (bloqueo real): 30 findings SSRF idénticos
   pivotaban entre sí factorialmente → timeout de tests. Fix: presupuesto
   global de 400 caminos explorados + cap de 25 cadenas + profundidad 6.
2. **Inconsistencia pivot vs fail-closed**: la regla pivot permitía
   extender el camino pero `_build_chain` lo rechazaba porque el consume
   no estaba transportado (SSRF→IDOR jamás encadenaba). Fix: distinción
   explícita data-flow/pivot con `transition` registrado en data_flow.
3. **Typo en compose_chains**: pasaba un ChainStep a `_grow` que esperaba
   findings dict → AttributeError inmediato. Fix: `_grow` opera sobre
   dicts; conversión a steps solo en `_build_chain`.

### Mejoras propuestas para tu versión (si difiere)
- Verificar que tu composición sea fail-closed: una cadena cuyo paso
  consume algo que nadie produjo debe descartarse, no "asumirse".
- Cap de exploración: sin él, catálogos grandes de findings cuelgan.
- Upsert por id en persistencia: re-save duplica registros si el archivo
  se reescribe entero sin filtrar por id.
- Aristas con confianza por paso (hypothesized hasta confirmación), no
  confianza fija de la cadena completa.

---

## 2. engine/defense_evasion.py — WAF fingerprinting + bypass + backoff + rotación

### Diseño
- **8 vendors + generic**: Cloudflare, Akamai, AWS WAF, Imperva, F5
  BIG-IP, ModSecurity, Sucuri, Fastly. Cada uno con passive_signals
  (headers/cookies/server), block_status, block_markers y
  **bypass_order** propio (encoding primero para Akamai, case folding
  para Cloudflare/ModSecurity, headers para F5/Fastly...).
- **Regla anti-falso-positivo**: un block-marker solo confirma vendor si
  YA hay una señal vendor-específica. "rate limit exceeded" no clasifica
  fastly; cae a `generic` 0.3.
- Active probe solo para Cloudflare (`/cdn-cgi/trace`), ejecutado por el
  caller vía callable inyectado — el módulo no hace red.
- **WAFBypassEngine**: rotación determinística por contador de intentos
  (sin RNG; reproducible). Estrategias: case_folding, encoding_chain
  (double URL-encode verificable), comment_split, whitespace_padding,
  header_spoof, chunked_transfer (PLAN de transporte con instrucciones),
  más nota h2_smuggling **canary-only** (desync = acción peligrosa,
  requiere approval del operador; nunca payloads por un desync sin
  confirmación).
- `record_result()` FIFO: el resultado se adjunta al plan más antiguo sin
  resolver (los planes se generan por adelantado). `exhausted()` = todas
  las estrategias del ciclo probadas y bloqueadas.
- **AdaptiveThrottle**: 429/503 → exponencial 2x (Retry-After honrado y
  capped a 120s), 403-WAF → 1.3x, 2xx → decae a base 1s. Jitter ±15%
  seeded (determinista por instancia). Nunca duerme: devuelve el wait.
- **FingerprintRotator**: perfiles UA/TLS/ciphers con digest estable
  (JA4-style hash del perfil), rotación recomendada tras 3 bloqueos
  consecutivos. PLANIFICA; el cambio TLS real es del HTTP client.
- **DefenseEvader facade**: `authorize_target()` fail-closed — sin
  PolicyEngine configurado, lanza PolicyDenied. Ningún método toca red.

### Defectos que encontré y corregí durante el desarrollo
1. **Falso positivo fastly**: "rate limit exceeded" 429 clasificaba
   fastly 0.55 (el block_marker genérico matcheaba antes del fallback).
   Fix: block-marker como doble-confirmación condicionada a señal pasiva
   vendor-específica.
2. **record_result invertido**: marcaba `attempts[-1]` (el plan más
   reciente) cuando los resultados llegan FIFO → `exhausted()` siempre
   False. Fix: primer intento sin `blocked` pendiente.
3. **ModSecurity invisible**: sus passive_signals eran solo
   server_header, pero ModSecurity casi nunca se anuncia en Server; se
   identifica por la block page. Fix: patrón `mod_security|modsecurity`
   en `body` como señal pasiva legítima.

### Mejoras propuestas para tu versión
- Verifica el orden de adjuntar resultados en tu engine de bypass: si
  generas planes por adelantado, el resultado FIFO al más antiguo
  pendiente (no al último generado) o `exhausted()` miente.
- Retry-After debe respetarse pero con cap (un Retry-After: 9999 no debe
  congelar el engagement).
- Loguea hash del payload transformado, no el payload (los intentos de
  bypass son material sensible que termina en logs).
- El backoff debe decaer con éxitos (si no, tras un 429 el scan queda
  lento para siempre).

---

## 3. engine/mcp_supply_chain.py — análisis estático de MCP servers

### Diseño
- **Corpus de 10 patrones** de inyección con peso/severidad: override
  (critical), role_claim (critical), cred_exfil (critical),
  sys_prompt_leak (high), tool_override (high), hidden_instruction
  (high), obfuscation/base64 (high), exfil_url (high, con allowlist de
  hosts benignos), urgent_framing (medium), scope_claim (medium).
- **Checks** (9 en total):
  - `description_injection` — corpus sobre tool descriptions.
  - `schema_poisoning` — corpus sobre campos de texto del JSON Schema
    (title/description/default/pattern/examples/const, anidados, con
    json_path en la evidencia: `$.properties.path.description`) + enum
    triggers (override/sudo/force/disable/bypass).
  - `name_collision` — duplicados exactos (severity high: routing
    attacker-controllable) y **typo-squat**: Levenshtein normalizado
    ≥ 0.8 **OR** containment (un nombre extiende al otro con verbos
    peligrosos: `calculator` → `calculator_exec`) con mismatch de riesgo.
  - `capability_escalation` — annotations que mienten: readOnlyHint en
    herramientas write/exec, destructiveHint=False en delete.
  - `response_injection` — corpus sobre tools/call results (content
    text items + structuredContent), porque el host modelo lee los
    resultados como datos.
  - `post_discovery_escalation` (drift) — diff de snapshots: herramientas
    nuevas tras el primer discovery (high si nombre peligroso),
    descripciones reescritas con NUEVOS patrones de inyección (high),
    schema cambiado (hash, medium), annotations cambiadas (low).
- Totalmente offline: `load_manifest()` acepta la shape MCP completa o
  bare server dict. IDs de finding deterministas (server|tool|check).
- `record_findings()` al grafo con source propio.

### Defectos que encontré y corregí durante el desarrollo
1. **`file`/`fs` en la lista de nombres peligrosos** → `file_reader`
   era "peligroso", rompiendo la detección de typo-squat (ambos nombres
   del par clasificaban peligroso = sin mismatch). Fix: solo
   verbos de escritura/ejecución/exfiltración; leer archivos no es
   peligroso per se.
2. **Trigram similarity under-scoreaba extensiones de sufijo**:
   `calculator` vs `calculator_exec` = 0.67 (bajo cualquier umbral
   razonable). Fix: Levenshtein normalizado + regla de containment con
   verbos peligrosos (la forma real del typo-squat de herramientas).
3. Threshold 0.92 inicial era inalcanzable para casi todo; recalibrado
   a 0.8 con el requisito de mismatch de riesgo (precisión conservada).

### Mejoras propuestas para tu versión
- Si usas similitud de nombres: valida contra pares reales
  (sufijo `_exec`, prefijo idéntico) — las métricas de n-gramas fallan
  exactamente en la forma más común de squat.
- El corpus de patrones es English-first: documéntalo como limitación
  (otro idioma requiere revisión manual).
- Response injection suele omitirse: el resultado de tools/call es
  texto no confiable que el modelo host lee — vale por sí solo como
  check.
- Drift: hashea el schema canónico (sort_keys) en vez de comparar
  dicts, o un cambio de orden de keys cuenta como drift falso.

---

## Criterios de auditoría aplicados (aplicables a tu implementación)

1. **Fail-closed por defecto**: sin scope/policy, nada se genera ni
   envía (PolicyDenied / cadena descartada sin data-flow cerrado).
2. **Oráculos por tipo**: cada paso de cadena tiene condición observable;
   sin oráculo no hay claim. Severidad combinada ≠ máximo de partes.
3. **Sin ejecución de red en módulos de planeamiento**: callables
   inyectados / planes de transporte, nunca sockets propios.
4. **Determinismo**: rotaciones y jitter seeded; sin `hash()` ni
   random global (lección de la auditoría del bridge).
5. **Persistencia honesta**: upsert por id, nunca duplicados, nunca
   se descartan datos corruptos silenciosamente.
6. **Anti falso positivo**: señales genéricas no clasifican vendor;
   block-markers solo confirman con señal vendor-específica.
7. **Grafo**: nodos con source propio, confianza hypothesized→
   demonstrated al confirmar, findings ajenos no se mezclan.
8. **Tests adversariales**: los casos límite (cadenas imposibles,
   429 sin Retry-After, typo-squat con sufijo, duplicado exacto,
   annotation mentirosa) tienen test propio, no solo happy path.

## Archivos de este paquete

```
engine/chain_exploit.py            (motor de cadenas)
engine/defense_evasion.py          (WAF/bypass/backoff/rotación)
engine/mcp_supply_chain.py         (análisis MCP estático)
engine/__init__.py                 (docstring actualizado — 3 líneas)
tests/test_chain_exploit.py        (32 tests)
tests/test_defense_evasion.py      (47 tests)
tests/test_mcp_supply_chain.py     (43 tests)
skills/ai-security/chain-exploit/SKILL.md
skills/ai-security/defense-evasion/SKILL.md
skills/ai-security/mcp-supply-chain/SKILL.md
AUDIT-3-modules.md                 (este documento)
```

Copiar a la raíz del repo quarry/ respetando las rutas. La suite completa
resultante: **648 tests, todos verdes** (`python3 -m pytest tests/ -q`).
