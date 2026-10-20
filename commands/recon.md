---
name: pt:recon
description: Ejecuta la fase de reconocimiento — pasivo, activo o ambos (full, default)
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /pt:recon [--passive|--active|--full]

Ejecuta descubrimiento sistemático de superficie contra el scope del
engagement activo. Por defecto corre `--full`: pasivo primero, activo
después, nunca al revés (el pasivo no toca el target, informa qué tan
agresivo puede ser el activo).

## Precondiciones

- Debe existir un engagement con fase `SCOPED` o posterior
  (`.pentest-state/engagement.json`). Si no existe o la fase es `INIT`,
  detener y señalar que falta `/pt:engage`.
- Releer el scope desde `.pentest-state/scope.json` antes de cualquier
  comando — no reutilizar scope de memoria de turnos anteriores, pudo
  cambiar con `/pt:scope`.
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
de tasa/horario de `/pt:engage`):
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

Para cada skill: leer su `SKILL.md` en `skills/recon/<skill>/` antes de
ejecutar — ahí están los comandos exactos y los gotchas de esa técnica.
Si el `SKILL.md` todavía no existe (plugin en construcción), aplicar la
metodología estándar de esa técnica y señalarlo en el output como gap de
contenido, no bloquear el recon por eso.

## Registro de resultados

- Cada asset nuevo descubierto (subdominio, IP, puerto, servicio, endpoint)
  se registra en `engine/coverage.py` vía `CoverageTracker.add_asset(asset)`
  — esto inicializa su fila en la matriz vuln_class × asset para
  `/pt:hunt` y `/pt:map` más adelante.
- Guardar output crudo de cada herramienta en `<audit_dir>/raw/<skill>-<timestamp>.<ext>`.
- Mantener un `asset-inventory.md` en `<audit_dir>/report/` (Write tool),
  actualizado incrementalmente: tabla de assets con tipo, fuente de
  descubrimiento, y notas.

## Tracking de cobertura

Al final de la corrida, imprimir qué sub-técnicas de recon se ejecutaron
y cuáles no (ej. "cloud-recon: skipped — no se detectó uso de cloud
provider en DNS/certs"). Esto no es opcional — es la cobertura que
`/pt:status` reporta después.

## Edge cases

- **Scope vacío o solo wildcards sin resolver**: antes de escanear, resolver
  qué hosts reales caen bajo el wildcard y confirmarlos contra
  `Scope.is_in_scope()` uno por uno.
- **Subdominio descubierto fuera del scope original** (ej. wildcard no
  incluía ese apex): NO escanearlo. Registrarlo como "descubierto,
  pendiente de autorización" y reportarlo al operador — puede ser una
  ampliación de scope legítima que requiere `/pt:scope --add` explícito
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
- Próximo paso recomendado: `/pt:map` (para construir los 5 mapas antes
  de hunting) o directamente `/pt:hunt` si el target es simple.
