# Gap Analysis — pentest-plugin vs ecosistema 2026

> Análisis exhaustivo comparando nuestro plugin contra 9 frameworks/repos
> del ecosistema de AI pentesting. Fecha: 2026-10-29.
>
> Repos analizados: Strix, PentAGI, HexStrike AI, opencode-pentester,
> pentest-ai-agents (0xSteph), CyberStrikeAI, RedAmon, CAI, CVEngine.
>
> Análisis previo (2026-10-21): H-mmer/pentest-agents, PiRanha, Claude-
> BugHunter, Shannon, Armur-Ai, ghostsecurity, utkusen, Cybermes, bbscope.

## Resumen ejecutivo

El plugin tiene cobertura sólida en: skills de caza por vuln class (40+),
chain analysis (engine + BFS + ENABLES_MAP), custody chain, evidence tags,
nuclei integration, priority classification (Fire/Smoke/Ice), validation
pipeline, template generation, SAST pipeline, OAST integration, app
profiling, y browser verification.

Es el **único** con hash-chain de custodia, triage brocards formales,
seven-question gate, y anti-fabrication rules explícitas.

Los gaps principales son **operacionales y de automatización**, no de
cobertura de técnicas. Los frameworks maduros se diferencian en
**inteligencia de ejecución** (decidir qué correr, cuándo parar, qué
alternativa usar) y **accountability de cobertura** (demostrar qué se
probó y qué quedó pendiente).

---

## Gaps identificados (priorizados)

### Tier 1 — Alto impacto, esfuerzo razonable

#### 1. Leads Ledger
**Fuente:** opencode-pentester
**Qué falta:** concepto formal de "lead pendiente" que bloquea el estado
"done" del engagement. Cada lead tiene motivo de cierre obligatorio
(explored, false-positive, dead, out-of-scope, duplicate).

**Por qué importa:** evita cerrar un engagement con superficie sin
explorar. Es accountability de cobertura.

**Dónde integrar:** `engine/findings.py` (nuevo modelo Lead) +
`commands/closeout.md` (gate: no close con leads abiertos).

**Esfuerzo:** medio.

---

#### 2. Decision Engine / Tool Recommender
**Fuente:** HexStrike AI, Strix
**Qué falta:** dado un AppProfile (que ya generamos en recon), recomendar
automáticamente qué skills/tools correr y con qué parámetros optimizados.
Hoy el operador elige manualmente.

**Por qué importa:** reduce tiempo de decisión y evita olvidar técnicas
relevantes al stack detectado.

**Dónde integrar:** `engine/router.py` (ya existe routing parcial) →
extender con mapeo AppProfile.tech_stack → skills recomendados +
parámetros sugeridos.

**Esfuerzo:** medio.

---

#### 3. Budget Exhaustion Report
**Fuente:** opencode-pentester
**Qué falta:** cuando se agota el budget/tiempo, producir reporte
automático de: (a) qué se probó, (b) qué leads quedaron abiertos,
(c) qué superficie no se testeó.

**Por qué importa:** accountability. "Me quedé sin tiempo" no es
aceptable sin decir qué quedó pendiente.

**Dónde integrar:** `engine/budget.py` + `engine/timeguard.py` →
generar coverage gap report al agotar.

**Esfuerzo:** bajo.

---

#### 4. Detection Pairing
**Fuente:** pentest-ai-agents (0xSteph)
**Qué falta:** que cada finding genere una regla de detección concreta
(Sigma mínimo, opcionalmente Splunk/KQL/YARA).

**Por qué importa:** eleva el valor del reporte para blue teams.
`skills/report/detection-opportunities` mapea controles defensivos pero
no genera reglas ejecutables.

**Dónde integrar:** extender
`skills/report/detection-opportunities/SKILL.md` + nuevo
`engine/detection_rules.py`.

**Esfuerzo:** medio.

---

#### 5. Adviser Pattern — Loop Detector mejorado
**Fuente:** PentAGI
**Qué falta:** `loop_detector.py` detecta loops pero no interviene
activamente sugiriendo estrategias alternativas. PentAGI tiene un
"Adviser" que tras N repeticiones propone cambio de enfoque.

**Por qué importa:** reduce waste de tokens y tiempo en caminos muertos.

**Dónde integrar:** `engine/loop_detector.py` → añadir
`suggest_alternative(context)` con mapeo de tool → alternativa +
estrategia diferente.

**Esfuerzo:** bajo.

---

#### 6. Tool Fallback Map
**Fuente:** HexStrike AI
**Qué falta:** mapeo de herramientas → alternativas cuando una falla
(gobuster→feroxbuster, nmap→rustscan, sqlmap→ghauri, etc.).

**Por qué importa:** resiliencia. Si una tool no está instalada o falla,
el agente sabe qué usar en su lugar.

**Dónde integrar:** `engine/tool_registry.py` → dict de fallbacks +
`engine/toolrunner.py` → auto-fallback.

**Esfuerzo:** bajo.

---

### Tier 2 — Impacto medio, esfuerzo variable

#### 7. Headless Mode + Exit Codes para CI
**Fuente:** Strix
**Qué falta:** modo sin interacción (`--headless`) con exit code no-zero
si hay findings sobre threshold. Para GitHub Actions / CI pipelines.

**Por qué importa:** integración CI/CD de clientes. Ya tenemos
`pr-scan.yaml` y `ci-scan.yaml` pero sin action ni exit codes formales.

**Dónde:** wrapper script o command `/run --headless`.
**Esfuerzo:** bajo.

---

#### 8. Diff-Scope Scanning
**Fuente:** Strix
**Qué falta:** limitar scan a archivos/endpoints cambiados en un PR.

**Por qué importa:** velocidad en CI — no re-escanear todo por cada PR.

**Dónde:** `engine/target_diff.py` (existe) → integrar con `pr-scan.yaml`
para filtrar scope por git diff.
**Esfuerzo:** bajo.

---

#### 9. Episodic Memory
**Fuente:** PentAGI
**Qué falta:** patrones de éxito/fracaso reutilizables entre engagements.
"La última vez que SQLi falló en Laravel 10, bypass con JSON content-type
funcionó."

**Dónde:** `engine/knowledge.py` → store de episodic patterns indexado
por (vuln_class, tech_stack, outcome).
**Esfuerzo:** medio.

---

#### 10. Evidence Replay
**Fuente:** CyberStrikeAI
**Qué falta:** request/response raw + timing completo de cada paso de
explotación para replay posterior.

**Dónde:** `engine/custody.py` → modo verbose que capture HTTP raw en
`.pentest-state/raw/`.
**Esfuerzo:** medio.

---

#### 11. Compliance Report Templates
**Fuente:** Strix, pentest-ai-agents
**Qué falta:** templates de reporte para SOC 2, ISO 27001, PCI DSS 4.0,
HIPAA, CIS Controls.

**Dónde:** `references/frameworks/` + extender
`skills/report/framework-mapping/SKILL.md`.
**Esfuerzo:** bajo (plantillas de mapeo).

---

#### 12. Attack Graph Persistente
**Fuente:** RedAmon
**Qué falta:** chain_engine es grafo en memoria. Un grafo persistente con
nodos tipados (Asset→Service→Endpoint→Parameter→Vulnerability) permitiría
queries cross-session.

**Dónde:** `engine/chain_engine.py` → serializar a
`.pentest-state/attack-graph.json` con nodos tipados.
**Esfuerzo:** medio.

---

#### 13. Guardrails Anti-injection
**Fuente:** CAI
**Qué falta:** detección de prompt injection en outputs de herramientas,
sanitización de Unicode homoglyphs en inputs. Un target malicioso podría
inyectar instrucciones en HTTP responses.

**Dónde:** `engine/guard.py` → `sanitize_tool_output(text)` y
`detect_injection_attempt(text)`.
**Esfuerzo:** medio.

---

#### 14. Credential Testing Skill
**Fuente:** pentest-ai-agents
**Qué falta:** hash identification, wordlist guidance, NIST 800-63B
password policy audit, spray planning con rate limiting.

**Dónde:** `skills/hunt/credential-testing/SKILL.md`.
**Esfuerzo:** bajo.

---

### Tier 3 — Útil pero menor prioridad

| # | Gap | Fuente | Esfuerzo |
|---|-----|--------|----------|
| 15 | Finding completion score (métrica numérica por finding) | opencode-pentester | Bajo |
| 16 | Command audit log con hash por ejecución | opencode-pentester | Medio |
| 17 | MCP client (consumir tools de MCP servers externos) | Strix | Medio |
| 18 | Playwright browser loop (exploits en headless) | Strix | Medio |
| 19 | Async tool execution con task tracking | HexStrike | Medio |
| 20 | CVE intelligence feeds activos (NVD/KEV/ExploitDB API) | HexStrike | Medio |
| 21 | Fix suggestion pipeline (generar parches) | RedAmon | Alto |
| 22 | Tracing/observabilidad de decisiones del agente | CAI | Medio |
| 23 | Fan-out/fan-in para recon paralelo | RedAmon | Medio |
| 24 | PoC generator (safe PoC reproducibles) | pentest-ai-agents | Medio |
| 25 | Post-exploitation skills (lateral, persistence, exfil) | pentest-ai-agents | Medio |

---

## Lo que NO adoptamos (y por qué)

| Idea | Por qué no |
|------|-----------|
| Django/Celery/PostgreSQL stack | Somos plugin CLI, no webapp |
| SQLite findings DB | JSON + custody hash-chain es más portable |
| Neo4j knowledge graph | Pesado para CLI; BFS en ENABLES_MAP cubre |
| Multi-tenancy | Single-operator plugin |
| Frontend web / React dashboard | Claude Code ES el frontend |
| Selenium como tool de exploitation | Preferimos Claude browser tools |
| CTF solver / reversing / forensics | Fuera de scope (web/infra pentest) |
| Wireless/SCADA/IoT exploitation | Nicho, fuera de foco |
| Social engineering / phishing infra | Fuera de scope actual |
| YAML pipeline DAGs | Nuestros workflows.yaml cubren secuenciación |
| Autofix PRs | Fuera de scope de pentest puro |
| Auto-instalación de tools | El operador controla su entorno |
| Monolito 17k líneas | Arquitectura modular > monolito |

---

## Lo que ya tenemos y es diferenciador

Capacidades que **ningún** repo analizado tiene:

1. **Custody hash-chain** (`engine/custody.py`) — integridad
   criptográfica de findings, no solo un log.
2. **Seven-question gate** — gate formal pre-explotación con 7 preguntas
   de seguridad operacional.
3. **Triage brocards** — reglas formales de triage como "brocardos"
   legales.
4. **Evidence tags** Demonstrated/Inferred/Unproven — los otros usan
   confirmed/unconfirmed binario.
5. **Anti-fabrication rules** — reglas explícitas contra inventar
   findings (ningún otro repo las tiene).
6. **OAST integration** (`engine/oast.py`) — out-of-band interaction
   management integrado.
7. **40+ hunt skills** con pasos detallados, gotchas, y chain anchors.
8. **Gotchas library** (14 archivos) — errores comunes por vuln class.
9. **Fire/Smoke/Ice priority** — clasificación determinista temporal.
10. **AI template generation** con validation de calidad.
11. **Rebuttal engine** — adversarial questioning de findings.
12. **Docker+Tor anon lab** — fail-closed para testing anónimo.

---

## Estado de implementación (2026-10-29)

### Tier 1 — TODOS IMPLEMENTADOS

| # | Gap | Archivo | Estado |
|---|-----|---------|--------|
| 1 | Leads Ledger | `engine/leads.py` | ✅ Lead model, LeadsStore, blocks_closeout(), custody integration |
| 2 | Decision Engine | `engine/decision_engine.py` | ✅ 43 stacks, 9 WAFs, 10 auth types, recommend(), recommend_for_finding() |
| 3 | Budget Exhaustion Report | `engine/budget.py:exhaustion_report()` | ✅ Coverage gaps + open leads + recommendation |
| 4 | Detection Pairing | `engine/detection_rules.py` | ✅ 20+ vuln classes → Sigma YAML, save_rules() |
| 5 | Adviser Pattern | `engine/loop_detector.py:suggest_alternative()` | ✅ TOOL_ALTERNATIVES + STRATEGY_ALTERNATIVES |
| 6 | Tool Fallback Map | `engine/tool_registry.py` TOOL_FALLBACKS + `references/tool-fallbacks.md` | ✅ 17 tools, fallback_for(), fallback_chain() |

### Tier 2 — TODOS IMPLEMENTADOS

| # | Gap | Archivo | Estado |
|---|-----|---------|--------|
| 7 | Headless Mode + Exit Codes | `engine/headless.py` | ✅ CI mode, exit codes, threshold-based pass/fail |
| 8 | Diff-Scope Scanning | `engine/target_diff.py:diff_from_git()` | ✅ git diff → route/config/dep files + endpoint extraction |
| 9 | Episodic Memory | `engine/episodic.py` | ✅ EpisodicStore, suggest_bypass(), suggest_alternative() |
| 10 | Evidence Replay | `engine/custody.py:capture_http_evidence()` | ✅ Raw HTTP in .pentest-state/raw/, attestation_block() |
| 11 | Compliance Templates | `references/frameworks/` (7 files) | ✅ PCI DSS 4.0, SOC 2, HIPAA, CIS v8, MITRE, NIST CSF, OWASP |
| 12 | Attack Graph Persistente | `engine/chain_engine.py:serialize_attack_graph()` | ✅ Typed nodes → attack-graph.json |
| 13 | Guardrails Anti-injection | `engine/guard.py` | ✅ sanitize_tool_output() + detect_injection_attempt() |
| 14 | Credential Testing | `skills/hunt/credential-testing/SKILL.md` | ✅ Hash ID, defaults, NIST 800-63B, spray |

### Tier 3 — TODOS IMPLEMENTADOS

| # | Gap | Archivo | Estado |
|---|-----|---------|--------|
| 15 | Finding completion score | `engine/findings.py:completion_score()` | ✅ Weighted 0-100, A/B/C/D grades, bulk_completion_scores() |
| 16 | Command audit log | `engine/custody.py:command_executed()` | ✅ Hash por ejecución, preview, duration |
| 17 | MCP client | `engine/mcp_client.py` + `references/mcp-integrations.md` | ✅ MCP tool consumption |
| 18 | Playwright browser loop | `engine/browser_loop.py` | ✅ Headless browser exploit verification |
| 19 | Async tool execution | `engine/async_tools.py` + `engine/fanout.py` | ✅ Concurrent task tracking |
| 20 | CVE intelligence feeds | `engine/cve_feeds.py` | ✅ NVD/KEV/ExploitDB integration |
| 21 | Fix suggestion pipeline | `engine/fix_suggest.py` | ✅ Remediation generation per finding |
| 22 | Tracing/observabilidad | `engine/tracing.py` | ✅ Decision trace events |
| 23 | Fan-out recon | `engine/fanout.py` | ✅ Parallel recon task orchestration |
| 24 | PoC generator | `engine/poc_gen.py` | ✅ Safe PoC generation |
| 25 | Post-exploitation | `skills/hunt/{post-exploitation,lateral-movement,data-exfiltration-test,persistence-check}` | ✅ 4 post-exploit skill categories |

**Resumen:** 25/25 gaps implementados. Todos los módulos importan correctamente.
56 engine modules, 90+ skills, 7 compliance frameworks, 17 tool fallbacks mapeados.
