---
name: quarry:recon
description: Ejecuta la fase de reconocimiento — pasivo, activo o ambos (full, default)
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:recon [--passive|--active|--full]

Ejecuta descubrimiento sistemático de superficie contra el scope del
engagement activo. Por defecto corre `--full`: pasivo primero, activo
después, nunca al revés (el pasivo no toca el target, informa qué tan
agresivo puede ser el activo).

## Precondiciones

- Debe existir un engagement con fase `SCOPED` o posterior
  (`.pentest-state/engagement.json`). Si no existe o la fase es `INIT`,
  detener y señalar que falta `/quarry:engage`.
- Releer el scope desde `.pentest-state/scope.json` antes de cualquier
  comando — no reutilizar scope de memoria de turnos anteriores, pudo
  cambiar con `/quarry:scope`.
- El guard de `hooks/hooks.json` (`engine/guard.py`) ya valida cada
  comando Bash contra scope automáticamente; aun así, antes de construir
  el comando, confirmar mentalmente que el target es el correcto.

## Argumento

- (ninguno) o `--full` — pasivo + activo, en ese orden.
- `--passive` — solo OSINT, DNS, certificados, archivos públicos, GitHub
  dorking, JS ya servido. Cero requests directas de escaneo al target.
- `--active` — asume que ya hay resultados pasivos útiles; si no los hay,
  avisar que el activo sin base pasiva es menos eficiente, pero proceder
  si el operador insiste.

## Metodología (breadth-first, por skill)

Pasiva (`skills/recon/passive-recon`, orden sugerido):
1. `dns-enumeration` — registros DNS, SPF/DKIM/DMARC, zone transfer attempt
2. `subdomain-discovery` — cert transparency, DNS brute, motores pasivos
3. `osint` — LinkedIn, Shodan/Censys histórico, Wayback Machine
4. `email-harvesting` — formatos de correo, empleados públicos
5. `github-dorking` — repos públicos de la org, secrets filtrados, forks
6. `cloud-recon` (modo pasivo) — buckets S3/GCS públicos, subdominios de
   cloud providers

Activa (`skills/recon/active-recon`, requiere scope confirmado y gate
de tasa/horario de `/quarry:engage`):
7. `port-scan` — nmap con `-oX` para output estructurado (ver
   `CLAUDE.md`: `--help` antes del primer uso de cualquier herramienta)
8. `service-enumeration` — banner grabbing, versiones, fingerprint sobre
   puertos abiertos del paso 7
9. `waf-fingerprint` — antes de cualquier fuzzing agresivo, para calibrar
   agresividad
10. `web-crawling` — spidering de rutas, sitemap, robots.txt
11. `js-analysis` — extraer endpoints, secrets, comentarios de bundles JS
    descubiertos en el crawl
12. `api-discovery` — Swagger/OpenAPI expuesto, GraphQL introspection,
    rutas inferidas desde JS
13. `tech-stack-fingerprint` — stack completo (frontend, backend, CDN,
    cloud provider) combinando todo lo anterior
14. `nuclei-reviewed` — seleccionar checks custom desde `AppProfile` con
    `NucleiRunner`; perfil `safe` por defecto, scope/redirects/OAST confinados,
    hashes y JSONL persistidos. Matches = leads; cero matches ≠ target limpio.

Para cada skill: leer su `SKILL.md` en `skills/recon/<skill>/` antes de
ejecutar — ahí están los comandos exactos y los gotchas de esa técnica.
Si el `SKILL.md` todavía no existe (plugin en construcción), aplicar la
metodología estándar de esa técnica y señalarlo en el output como gap de
contenido, no bloquear el recon por eso.

## Registro de resultados

- Antes de ejecutar, consultar `engine/tool_registry.py` por **capacidad** (DNS, HTTP probe,
  crawl, JS, contenido, screenshots, etc.), registrar herramienta/versión/backend elegidos y
  usar el fallback determinista. Una capacidad sin backend es `tool_unavailable`, nunca éxito.
- Normalizar cada handoff con `engine/recon_pipeline.py`: descubrimiento → filtro de scope →
  deduplicación → resolución/HTTP → fingerprint → crawl/JS/históricos → screenshots → ranking.
  Cada observación conserva fuente, etapa, timestamp, completitud y metadatos; los candidatos
  fuera de scope quedan `out_of_scope_pending_authorization` y no pasan a sondas activas.
- Priorizar por señales explícitas (legacy/olvidado, admin, import/export, upload, webhooks,
  integraciones, multi-tenant y diferencias free/paid), guardando score y razones. El score
  ordena trabajo; no es severidad ni evidencia de vulnerabilidad.
- Para brute force o fuzzing, indexar listas locales con `engine/wordlists.py` y persistir path,
  SHA-256, tamaño, tecnología y criterios de selección en el run/task. No improvisar `wordlist.txt`.
- Cada asset nuevo se registra con `CoverageTracker.add_asset(asset)`. Cada
  endpoint descubierto se agrega con `add_surface`, incluyendo método,
  parámetros e identidades conocidas; así `/quarry:hunt` no colapsa toda una
  aplicación en una sola celda por host.
- Guardar output crudo completo mediante `ArtifactStore`, con SHA-256 e índice; no depender de
  vistas truncadas del terminal.
- Mantener un `asset-inventory.md` en `<audit_dir>/report/` (Write tool),
  actualizado incrementalmente: tabla de assets con tipo, fuente de
  descubrimiento, prioridad y notas. Crear snapshot/diff con `TargetDiffEngine` al terminar.

## Tracking de cobertura

Al final de la corrida, imprimir qué sub-técnicas de recon se ejecutaron
y cuáles no (ej. "cloud-recon: skipped — no se detectó uso de cloud
provider en DNS/certs"). Esto no es opcional — es la cobertura que
`/quarry:status` reporta después.

## Edge cases

- **Scope vacío o solo wildcards sin resolver**: antes de escanear, resolver
  qué hosts reales caen bajo el wildcard y confirmarlos contra
  `Scope.is_in_scope()` uno por uno.
- **Subdominio descubierto fuera del scope original** (ej. wildcard no
  incluía ese apex): NO escanearlo. Registrarlo como "descubierto,
  pendiente de autorización" y reportarlo al operador — puede ser una
  ampliación de scope legítima que requiere `/quarry:scope --add` explícito
  primero.
- **WAF/rate-limit agresivo detectado**: bajar velocidad, documentar el
  umbral observado, no reintentar ciegamente (máx. 3 reintentos idénticos
  por regla del `CLAUDE.md` del plugin).
- **Rerun sobre un engagement ya en fase `HUNTING` o posterior**: permitido
  (recon incremental), pero advertir que no se debe repetir trabajo ya
  cubierto — mirar `coverage.json` antes de rehacer.

## Transición de fase

Al terminar, si la fase actual es `SCOPED`, transicionar a `RECON`
(`state.transition(Phase.RECON)`). Si ya se había pasado por `MAPPED` o
`HUNTING` (recon incremental), no retroceder la fase.

## Output esperado

- Tabla de assets descubiertos (tipo, valor, fuente).
- Resumen pasivo vs activo ejecutado, con lo que se omitió y por qué.
- Ruta de `asset-inventory.md` y de los raw outputs.
- Próximo paso recomendado: `/quarry:map` (para construir los 5 mapas antes
  de hunting) o directamente `/quarry:hunt` si el target es simple.
