# Depth Layers — 2026-10-21

> Segunda ola de mejoras, posterior al GAP-ANALYSIS original. El gap analysis
> cubrió lo que otros plugins tenían y nosotros no; esta ola agrega lo que
> NINGÚN plugin del ecosistema tenía resuelto bien. Fuentes: Stickman230/claude-pentest
> (Kali MCP), trailofbits/skills (static-analysis, supply-chain, variant-analysis,
> brocards, testing-handbook), usestrix/strix (SARIF, fix-retest loop, CI scanning),
> KeygraphHQ/shannon (re-exploit), penetration-tester (chain-of-custody),
> SnailSploit (garak), Eyadkelleh/awesome-claude-skills-security (payload corpus).

## Engine (6 módulos nuevos)

| Módulo | Capa | Problema que resuelve |
|--------|------|----------------------|
| `oast.py` | OOB/OAST | Vulns ciegas (blind SSRF/XSS/XXE/RCE, DNS exfil) no podían llegar a `Demonstrated`. Tokens únicos de correlación + registro de interacciones + evidence records. |
| `sessions.py` | Identidades | IDOR/BAC se testeaba improvisando headers. Sesiones nombradas por identidad (userA/userB/admin/anon), diffs cross-identidad registrados, `has_pair()` como gate de hunting. |
| `knowledge.py` | Memoria acumulativa | El brain era por-engagement. Knowledge base persistente y anonimizada de efectividad de técnicas (qué bypass funcionó contra qué stack/WAF). |
| `custody.py` | Cadena de custodia | findings.py hasheaba evidencia; ahora hay log append-only hash-chained de TODO el engagement (scope, gates, evidencia, exports) — attestable, con detección de alteración. |
| `toolrunner.py` | Ejecución | Backends declarados: local / Kali REST (MCP-Kali-Server style) / Docker pineado. Aplica mecánicamente las reglas CLI (`--help` antes de uso, timeouts, 3-retry cap). |
| `exporters.py` | Integración | SARIF 2.1.0 (code scanning), JSON (ticketing), CSV. Solo exporta VALIDATED/REPORTED. Todo export queda en custody. |

## Skills (11 nuevas)

- **core/oob-interactions** — disciplina OAST: cuándo es obligatoria, tiers de
  correlación, gotchas (DNS-only ≠ fetch, egress proxies, WAF pre-fetch).
- **core/session-context** — protocolo de identidades paralelas para
  access-control; interpretación de diffs (404≠403, UUIDs no arreglan authz).
- **hunt/fuzzing** — schemathesis/RESTler (schema-driven), radamsa (mutación),
  parser fuzzing, coverage-guided con source; crash triage anti-ruido.
- **hunt/grpc** — reflection, schema reconstruction, metadata auth, IDOR a
  nivel mensaje, grpc-web divergence.
- **sast/supply-chain-audit** — SCA con osv-scanner/grype/govulncheck +
  reachability + EPSS/KEV + dependency confusion. Scanner dump ≠ finding.
- **sast/variant-analysis** — un finding confirmado → patrón → barrido de
  siblings (semgrep/CodeQL); familia en un solo finding, no 12 duplicados.
- **sast/static-analysis-toolkit** — CodeQL/Semgrep reales + ingest SARIF como
  leads; export de vuelta a SARIF para el code scanning del cliente.
- **validate/triage-brocards** — 7 brocards (B1–B7) para accept/dismiss/
  info-needed en <2 min por candidato, con decisiones auditables.
- **report/detection-opportunities** — capa purple team: data sources ATT&CK,
  telemetría esperada, idea de detección, replay test por finding.
- **ai-security/llm-fuzzing** — garak/PyRIT para breadth automatizado de
  prompt injection; hits son leads (B3), confirmación manual.
- (sast) categoría `sast/` ahora validada explícitamente.

## Workflows / comandos / presets

- `workflows/retest.yaml` + `/pt:retest` — verificación de remediación:
  FIXED/PARTIAL/NOT_FIXED/REGRESSED con evidencia, + variant-sweep post-fix.
- `workflows/pr-scan.yaml` + `presets/ci-scan.yaml` — modo CI: estático,
  sobre el diff del PR, SARIF a anotaciones, sin tráfico activo.
- `/pt:export` — SARIF/JSON/CSV con custody logging.

## Benchmark harness

`benchmarks/` — ground truth curada (juice-shop 16, crapi 10, dvwa 9),
`score.py` (recall/recall-required/precision/evidence-integrity, exit code
como regression gate), README con reglas del harness. CI:
`.github/workflows/validate.yml` corre validación estructural + tests en
cada push; benchmark completo on-demand. Tests nuevos: `test_engine.py`
(6 módulos), `test_benchmark_score.py` (fixture sintético).

## Scoring y reportes

- CVSS 3.1 → **4.0** (vector primario, 3.1 opcional por compatibilidad) en
  CLAUDE.md + finding-template (tabla de métricas actualizada: AT, UI
  N/P/A, VC/VI/VA vs SC/SI/SA).
- **EPSS + CISA KEV** como ejes de prioridad (no de severidad):
  `references/cvss4-epss-kev.md` define composición.
- finding-template: sección Detection Opportunities + referencia a custody.
- engagement-report: sección Detection Coverage + appendix de cadena de
  custodia + tabla de artefactos machine-readable.

## Payload corpus

`references/payloads/` — 10 archivos curados (sqli, xss, ssrf, ssti, xxe,
lfi-rfi, cmd-injection, jwt, graphql, llm-injection) con notas de uso y
gotchas; base offline para hunting y para el paso de confirmación manual.

## Lo que esto habilita que antes era imposible

1. Reportar blind vulns como `Demonstrated` (OAST).
2. IDOR con evidencia atribuible por identidad (sessions).
3. Mejora acumulativa entre engagements (knowledge).
4. Reporte defendible en contexto legal/compliance (custody).
5. Reproducibilidad de tooling (toolrunner).
6. Findings en el pipeline del cliente (SARIF + retest loop).
7. Saber si el plugin mejora: recall medible (benchmarks).
