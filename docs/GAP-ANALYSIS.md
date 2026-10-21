# Gap Analysis — Plugin vs Ecosystem

Fuentes: H-mmer/pentest-agents (50 agents, 26 cmds), Falcon-Forge/PiRanha (53 agents),
elementalsouls/Claude-BugHunter (82 skills), 0xSteph/pentest-ai-agents (50 agents),
usestrix/strix (70k stars), KeygraphHQ/shannon (49k), Armur-Ai/Pentest-Swarm-AI,
ghostsecurity/skills, utkusen/sast-skills, Cybermes, exploitation-validator, bbscope, +30 más.

---

## Batch 1: Hunting effectiveness (por qué nuestro recon es pobre)

### 1.1 Surface Probes obligatorios (pentest-agents)
**Gap:** Nuestras skills de recon describen metodología pero no ejecutan probes concretos.
pentest-agents tiene 9 probes A-I mandatorios con curl puro ANTES de despachar hunters:
- A: path enum (.well-known/*, _next/data/*, common admin paths)
- B: HTTP method matrix (OPTIONS/TRACE/PROPFIND/MKCOL per path)
- C: cache-deception probes (.css/.js suffix + cf-cache-status check)
- D: CRLF/response-splitting (%0d%0a, unicode variants)
- E: CORS preflight matrix (null, subdomain bypass regexes, file://)
- F-I: HTTP/2 desync, header injection, etc.
**Acción:** Crear `skills/recon/surface-probes/SKILL.md` con los 9 probes como steps
ejecutables. El command `/pt:recon` debe correrlos obligatoriamente post-discovery.

### 1.2 AppProfile-first invariant (PiRanha)
**Gap:** No hay gate que impida hunting sin perfil de aplicación completo.
PiRanha: "No agent fires a payload until AppReviewAgent has produced an AppProfile."
**Acción:** Crear `engine/app_profile.py` — genera perfil (tech stack, auth flows,
roles, API style, AI features) que es prerequisito para la fase HUNTING.

### 1.3 Per-class chain anchors / FEEDER discipline (pentest-agents)
**Gap:** Nuestras hunt skills terminan al encontrar el bug. No prueban anchors de chain.
Ejemplo: open-redirect encontrado → probar redirect_uri en cada OAuth client.
SSRF encontrado → probar IMDS inmediatamente. XSS → probar cookie theft + CSRF forge.
**Acción:** Agregar sección "## Chain Anchors" a cada hunt skill con 3-6 probes
obligatorios antes de declarar el finding completo.

### 1.4 Never-submit list (pentest-agents)
**Gap:** No tenemos lista de non-findings que se deben rechazar automáticamente.
Lista: missing headers solo, GraphQL introspection solo, self-XSS, open-redirect solo,
SSRF DNS-only sin impacto, CORS wildcard sin exfil credencialed, logout CSRF, etc.
**Acción:** Crear `references/never-submit.md` y que el validator lo consulte.

### 1.5 Mistakes log (pentest-agents)
**Gap:** No inyectamos errores comunes en los agentes.
Top errores: fingerprint ≠ confirmed, webpack-stripped misses 60-90% API surface,
probabilistic chains claimed as reproducible, scanner-only ≠ finding.
**Acción:** Crear `references/common-mistakes.md`, inyectar en agent preambles.

---

## Batch 2: Intelligence layer (brain + knowledge)

### 2.1 Brain / capability graph (pentest-agents, PiRanha)
**Gap:** Nuestro engine tiene state pero no intelligence. No trackea:
- Vectores exhaustados (qué ya se probó y falló)
- Vectores activos (qué está en progreso)
- Capabilities ganadas (qué puede hacer el atacante ahora)
pentest-agents: `brain.py` con JSON de capabilities + exhaustion per engagement.
PiRanha: CAP taxonomy (cada finding tagged con gives/needs).
**Acción:** Crear `engine/brain.py` — capability graph, exhaustion tracking,
briefing automático antes de cada agent dispatch.

### 2.2 Writeup/technique knowledge base (pentest-agents, Cybermes)
**Gap:** No consultamos writeups existentes antes de probar una técnica.
pentest-agents: MCP writeup-search obligatorio antes de cada step.
Cybermes: búsqueda offline en PayloadsAllTheThings/HackTricks.
**Acción:** Crear `references/payloads/` con cheatsheets por clase, y una skill
`skills/core/research-first/SKILL.md` que fuerce consulta antes de test.

### 2.3 Capability-graph chain improvements (PiRanha)
**Gap:** Nuestro chain_engine tiene KNOWN_CHAINS (pattern matching) pero no modela
capabilities como grafo dirigido con pathfinding.
PiRanha: networkx DiGraph, finds paths from entry to crown jewels weighted by
trust-boundary crossing (unauth→user→priv→admin→host→cloud).
**Acción:** Agregar mode "capability-graph" a `engine/chain_engine.py` con gives/needs
taxonomy y pathfinding BFS weighted.

---

## Batch 3: Validation hardening

### 3.1 Independent re-exploitation (Shannon, exploitation-validator, PiRanha)
**Gap:** Nuestro rebuttal es question-based. No re-ejecuta los PoCs.
Shannon: "No exploit, no report". 6-stage pipeline con reconciliación.
PiRanha ValidatorAgent: re-runs PoC in cold session (fresh cookie jar),
requires control-vs-attack differential.
exploitation-validator: 5/42 findings survived (88% false positive rate).
**Acción:** Agregar modo "re-exploit" al `engine/rebuttal.py` que lance un agente
ciego para reproducir el finding desde cero.

### 3.2 Evidence immutability (Iceo96)
**Gap:** Nuestra evidencia no tiene hash. Se puede alterar post-hoc.
**Acción:** SHA-256 hash de cada evidence artifact en FindingsStore.

### 3.3 Hunt mode severity gating (PiRanha)
**Gap:** No diferenciamos threshold por modo (bounty vs pentest vs audit).
PiRanha: bounty≥8.0, pentest≥4.0, comprehensive≥0.0. Sub-threshold archivado
para chain material, no descartado.
**Acción:** Agregar `mode` a engagement config, severity gates en validator.

### 3.4 Browser verification agent (pentest-agents)
**Gap:** No tenemos verificación en browser real. "browser-verifier: no finding
ships without browser verification."
**Acción:** Crear `agents/browser-verifier.md` que use Claude Browser tools.

---

## Batch 4: Integration & tooling

### 4.1 MCP server definitions (Burp, Caido)
**Gap:** No tenemos integraciones con proxies reales.
PortSwigger/mcp-server (oficial), six2dez/burp-ai-agent (53 tools),
Cy-S3c/BurpMCP-Ultra (150 tools), caido/skills.
**Acción:** Documentar integraciones en `references/mcp-integrations.md`,
crear skills que asuman disponibilidad de Burp/Caido MCP.

### 4.2 SAST pipeline (pentest-agents, utkusen/sast-skills)
**Gap:** No tenemos análisis de código fuente.
pentest-agents: 7 agentes (file-ranker → entry-mapper → danger-mapper →
flow-tracer(Opus) → gap-analyzer(Opus) → devils-advocate → hunter).
utkusen/sast-skills: 13 subagentes en paralelo, detección en 2 fases.
**Acción:** Crear `skills/sast/` con pipeline de análisis estático.

### 4.3 Credential vault (PiRanha, pentest-agents)
**Gap:** No tenemos manejo seguro de credenciales de test.
**Acción:** Crear `engine/vault.py` — base64 + 1Password op CLI integration.

### 4.4 Scope import from platforms (bbscope, pentest-agents bounty MCP)
**Gap:** Scope es manual. bbscope agrega H1/Bugcrowd/Intigriti/YesWeHack/Immunefi.
**Acción:** Skill `skills/core/scope-import/SKILL.md` que use bbscope.

---

## Batch 5: Efficiency & UX

### 5.1 Deterministic router (PiRanha)
**Gap:** Nuestros workflows son documentos YAML descriptivos, no ejecutables.
PiRanha: TypeScript router con engagement type → agent groups, CI-validated.
**Acción:** Crear `engine/router.py` — mapeo estático tipo→fases→agentes.

### 5.2 Cost/ROI tracking (pentest-agents)
**Gap:** Nuestro budget cuenta tool calls pero no tokens/costo real.
**Acción:** Extender `engine/budget.py` con tracking de tokens y ROI.

### 5.3 Monitor agent (pentest-agents)
**Gap:** No tenemos monitoreo en background de cambios en el target.
**Acción:** Crear `agents/monitor.md` — baseline/check/scope modes.

---

## Prioridad recomendada

| Batch | Impacto en calidad de hunting | Esfuerzo |
|-------|-------------------------------|----------|
| 1     | CRÍTICO (esto es por qué el recon fue pobre) | Medio |
| 2     | ALTO (inteligencia acumulativa)              | Alto   |
| 3     | ALTO (elimina falsos positivos)              | Medio  |
| 4     | MEDIO (integraciones externas)               | Alto   |
| 5     | BAJO-MEDIO (eficiencia)                      | Medio  |
