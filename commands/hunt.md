---
name: quarry:hunt
description: Fase de hunting por clase de vulnerabilidad — todas las clases/assets o un subconjunto filtrado
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:hunt [class] [--asset <asset>]

Ejecuta las skills `*` contra el scope. Sin argumentos, corre TODAS
las clases contra TODOS los assets, breadth-first (regla de `CLAUDE.md`
del plugin: cubrir ancho antes que profundidad). Con `[class]`, limita a
esa clase sobre todos los assets. Con `--asset <asset>`, limita a ese
asset sobre todas las clases (o la clase dada, si ambos se combinan).

## Precondición

- Fase `MAPPED` o `HUNTING`. Si el engagement está en `RECON` sin pasar
  por `/quarry:map`, advertir que hunting sin mapas pierde contexto de
  trust/identity/capability — permitir si el operador insiste (target
  trivial), pero dejarlo registrado.
- Releer `coverage.json` y `findings.json` existentes antes de arrancar
  — no reescanear una celda `tested_clean` o `finding_detected` ya
  registrada salvo que el operador pida explícitamente re-test.

## Mapeo clase → skill

`engine/coverage.py` define `ALL_VULN_CLASSES` (40 clases). Cada clase
mapea a una skill en `skills/hunt/`; varias clases comparten una skill
cuando son variantes de la misma técnica:

| Skill (`skills/hunt/<x>`)   | Vuln classes cubiertas                              |
|------------------------------|------------------------------------------------------|
| sqli                   | sqli                                                 |
| xss                    | xss-reflected, xss-dom, xss-stored                  |
| ssrf                   | ssrf                                                |
| idor                   | idor                                                |
| csrf                   | csrf                                                |
| rce                    | rce                                                  |
| ssti                   | ssti                                                 |
| xxe                    | xxe                                                   |
| lfi-rfi                | lfi, rfi                                             |
| auth-bypass            | auth-bypass                                          |
| race-condition         | race-condition                                       |
| cors                   | cors                                                  |
| open-redirect          | open-redirect                                        |
| info-disclosure        | info-disclosure                                      |
| deserialization        | deserialization                                       |
| graphql                | graphql                                              |
| websocket              | websocket                                            |
| jwt                    | jwt                                                   |
| oauth                  | oauth                                                 |
| api-abuse              | api-abuse                                            |
| file-upload            | file-upload                                          |
| cache-poisoning        | cache-poisoning                                      |
| http-smuggling         | http-smuggling                                        |
| subdomain-takeover     | subdomain-takeover                                    |
| crlf-injection         | crlf-injection                                        |
| clickjacking           | clickjacking                                          |
| host-header            | host-header-injection                                 |
| parameter-pollution    | parameter-pollution                                   |
| prototype-pollution    | prototype-pollution                                   |
| mass-assignment        | mass-assignment                                       |
| broken-access-control  | broken-access-control                                 |
| business-logic         | business-logic                                        |
| rate-limiting          | rate-limiting                                         |
| password-reset         | password-reset                                        |
| 2fa-bypass             | 2fa-bypass                                            |
| session-management     | session-management                                    |
| email-injection        | email-injection                                        |

Si se pasa `[class]` y no matchea ni el nombre de skill ni una clase de
`ALL_VULN_CLASSES` (comparar con normalización `lower().replace('_','-')`),
listar las clases válidas y pedir que se repita el comando.

## Pasos exactos

1. Resolver el set granular de celdas: `asset × clase × endpoint × método ×
   parámetro × identidad × técnica`. Sin argumentos se cubren todas las celdas
   registradas en `coverage.json`; los filtros `[class]` y `--asset` acotan ese
   conjunto sin borrar la granularidad.
2. Filtrar contra `coverage.get_gaps()` salvo re-test explícito. Una celda
   `partial`, `inconclusive`, `blocked`, `tool_unavailable` o `deferred` sigue
   siendo un gap; no equivale a cobertura concluyente.
3. Para cada celda, leer su skill y usar `ToolRunner` o `ProtectedHTTPClient`.
   Guardar primero los artefactos crudos con `ArtifactStore`; incluir sus IDs en
   el resultado. Si falta la skill, registrar `blocked` con gap de contenido, no
   improvisar y marcar cobertura concluyente.
4. Ejecutar la prueba. Resultado posible:
   - **Sin hallazgo, evidencia completa** → `mark_tested(...,
     status="tested_clean", evidence_artifacts=[...], evidence_complete=True)`.
   - **Hallazgo candidato** → crear `Finding` en `DETECTED` y marcar
     `finding_detected` solo con referencias de evidencia completas.
   - **Timeout, respuesta incompleta o resultado ambiguo** → `inconclusive`.
   - **Herramienta ausente** → `tool_unavailable`.
   - **No soportado por la tecnología** → `not_applicable` con evidencia de por qué.
   - **Fuera de scope** → `out_of_scope`; **gate pendiente** → `blocked`;
     **pospuesto** → `deferred`. Nunca usar `skipped` como cajón genérico.
5. Un finding en `DETECTED` no es definitivo — no reportarlo como
   confirmado todavía. Intentar reproducirlo manualmente una vez (no en
   loop) para subirlo a `CONFIRMED` vía
   `FindingsStore.update_status(id, FindingStatus.CONFIRMED, reason=...)`
   si la reproducción es limpia; si no reproduce, dejarlo en `DETECTED`
   con nota, o matarlo (`KILLED`) si era claramente falso positivo del
   scanner.
6. Respetar budget: antes de cada clase nueva, chequear
   `BudgetManager.record_call(phase="hunting", command=...)`. Si
   `allowed=False`, detener y escalar al operador (regla de `CLAUDE.md`
   del plugin: 80% de budget sin progreso → escalar).

## Gate humano

Cualquier técnica que module estado del target (escritura, mutación de
datos reales, envío de emails/SMS reales, condiciones de carrera contra
funciones financieras) requiere confirmación explícita del operador
ANTES de ejecutar, incluso en modo "breadth-first" sin argumentos. No
hacer excepciones por volumen — si el hunting completo requiere 10
confirmaciones, pedirlas todas, agrupadas si es posible para no
interrumpir el flujo innecesariamente.

## Edge cases

- **Clase no aplicable a la tecnología del asset** (ej. `ssti` en
  un asset que sirve solo JSON estático sin motor de templates): marcar
  `skipped` con razón concreta ("no se detectó motor de templates en
  tech-stack-fingerprint"), no "tested_clean" — son estados distintos.
- **Asset deja de responder / rate-limit agresivo**: pausar esa fila,
  continuar con otros assets, documentar el umbral, no reintentar en
  loop (máx. 3 veces).
- **Mismo root cause en múltiples celdas** (ej. falta de output
  encoding afecta 3 endpoints distintos bajo xss-reflected): registrar
  como findings separados por ahora — la deduplicación formal es trabajo
  de `/quarry:validate` (paso de `dedup`), no de hunt.
- **Hallazgo que claramente pertenece a otra clase** (ej. buscando SSRF
  se encuentra un IDOR): registrarlo en la clase correcta
  inmediatamente, no forzarlo en la celda que se estaba probando.

## Output esperado

- Resumen de la corrida: celdas probadas, limpias, con hallazgo, y
  skipped — con razones.
- Lista de findings nuevos (ID, clase, asset, severidad preliminar,
  status).
- Ratio de cobertura actualizado (`CoverageTracker.summary()`).
- Próximo paso recomendado: si quedan ≥2 findings `CONFIRMED` o
  `EXPLOITED`, `/quarry:chain`; si no, seguir con celdas pendientes o
  `/quarry:validate` sobre lo que ya hay.
