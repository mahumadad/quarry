---
name: pt:hunt
description: Fase de hunting por clase de vulnerabilidad — todas las clases/assets o un subconjunto filtrado
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:hunt [class] [--asset <asset>]

Ejecuta las skills `hunt-*` contra el scope. Sin argumentos, corre TODAS
las clases contra TODOS los assets, breadth-first (regla de `CLAUDE.md`
del plugin: cubrir ancho antes que profundidad). Con `[class]`, limita a
esa clase sobre todos los assets. Con `--asset <asset>`, limita a ese
asset sobre todas las clases (o la clase dada, si ambos se combinan).

## Precondición

- Fase `MAPPED` o `HUNTING`. Si el engagement está en `RECON` sin pasar
  por `/pt:map`, advertir que hunting sin mapas pierde contexto de
  trust/identity/capability — permitir si el operador insiste (target
  trivial), pero dejarlo registrado.
- Releer `coverage.json` y `findings.json` existentes antes de arrancar
  — no reescanear una celda `tested_clean` o `finding_detected` ya
  registrada salvo que el operador pida explícitamente re-test.

## Mapeo clase → skill

`engine/coverage.py` define `ALL_VULN_CLASSES` (38 clases). Cada clase
mapea a una skill en `skills/hunt/`; varias clases comparten una skill
cuando son variantes de la misma técnica:

| Skill (`skills/hunt/<x>`)   | Vuln classes cubiertas                              |
|------------------------------|------------------------------------------------------|
| hunt-sqli                   | sqli                                                 |
| hunt-xss                    | xss-reflected, xss-dom, xss-stored                  |
| hunt-ssrf                   | ssrf                                                |
| hunt-idor                   | idor                                                |
| hunt-csrf                   | csrf                                                |
| hunt-rce                    | rce                                                  |
| hunt-ssti                   | ssti                                                 |
| hunt-xxe                    | xxe                                                   |
| hunt-lfi-rfi                | lfi, rfi                                             |
| hunt-auth-bypass            | auth-bypass                                          |
| hunt-race-condition         | race-condition                                       |
| hunt-cors                   | cors                                                  |
| hunt-open-redirect          | open-redirect                                        |
| hunt-info-disclosure        | info-disclosure                                      |
| hunt-deserialization        | deserialization                                       |
| hunt-graphql                | graphql                                              |
| hunt-websocket              | websocket                                            |
| hunt-jwt                    | jwt                                                   |
| hunt-oauth                  | oauth                                                 |
| hunt-api-abuse              | api-abuse                                            |
| hunt-file-upload            | file-upload                                          |
| hunt-cache-poisoning        | cache-poisoning                                      |
| hunt-http-smuggling         | http-smuggling                                        |
| hunt-subdomain-takeover     | subdomain-takeover                                    |
| hunt-crlf-injection         | crlf-injection                                        |
| hunt-clickjacking           | clickjacking                                          |
| hunt-host-header            | host-header-injection                                 |
| hunt-parameter-pollution    | parameter-pollution                                   |
| hunt-prototype-pollution    | prototype-pollution                                   |
| hunt-mass-assignment        | mass-assignment                                       |
| hunt-broken-access-control  | broken-access-control                                 |
| hunt-business-logic         | business-logic                                        |
| hunt-rate-limiting          | rate-limiting                                         |
| hunt-password-reset         | password-reset                                        |
| hunt-2fa-bypass             | 2fa-bypass                                            |
| hunt-session-management     | session-management                                    |
| hunt-email-injection        | email-injection                                        |

Si se pasa `[class]` y no matchea ni el nombre de skill ni una clase de
`ALL_VULN_CLASSES` (comparar con normalización `lower().replace('_','-')`),
listar las clases válidas y pedir que se repita el comando.

## Pasos exactos

1. Resolver el set de (asset × clase) a cubrir en esta corrida:
   - Sin argumentos: producto cartesiano completo de assets registrados
     en `coverage.json` × las 38 clases.
   - Con `[class]`: todos los assets × esa clase (y sus variantes de la
     tabla, si la skill cubre varias).
   - Con `--asset`: ese asset × (clase dada o las 38).
2. Filtrar el set contra `coverage.get_gaps()` si se quiere evitar
   reproceso; si el operador pide re-test explícito, ignorar el filtro
   para esas celdas puntuales.
3. Para cada celda, leer `skills/hunt/<skill>/SKILL.md` (si existe) antes
   de probar esa clase en ese asset — ahí están los comandos, gotchas y
   validation gate específicos. Si la skill no está escrita aún,
   aplicar la metodología OWASP estándar de esa clase y marcarlo como
   gap de contenido.
4. Ejecutar la prueba. Resultado posible:
   - **Sin hallazgo** → `coverage.mark_tested(asset, vuln_class, status="tested_clean", skill_used=...)`.
   - **Hallazgo candidato** → crear `Finding` en `engine/findings.py`
     (`FindingsStore.add`) con `status=DETECTED`, evidencia inicial, y
     `coverage.mark_tested(..., status="finding_detected", ...)`.
   - **Bloqueado/no aplicable** (fuera de scope, requiere exploit
     destructivo sin gate humano, o el asset no soporta la técnica) →
     `coverage.mark_skipped(asset, vuln_class, reason=...)`.
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

- **Clase no aplicable a la tecnología del asset** (ej. `hunt-ssti` en
  un asset que sirve solo JSON estático sin motor de templates): marcar
  `skipped` con razón concreta ("no se detectó motor de templates en
  tech-stack-fingerprint"), no "tested_clean" — son estados distintos.
- **Asset deja de responder / rate-limit agresivo**: pausar esa fila,
  continuar con otros assets, documentar el umbral, no reintentar en
  loop (máx. 3 veces).
- **Mismo root cause en múltiples celdas** (ej. falta de output
  encoding afecta 3 endpoints distintos bajo xss-reflected): registrar
  como findings separados por ahora — la deduplicación formal es trabajo
  de `/pt:validate` (paso de `dedup`), no de hunt.
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
  `EXPLOITED`, `/pt:chain`; si no, seguir con celdas pendientes o
  `/pt:validate` sobre lo que ya hay.
