---
name: quarry:map
description: Genera los 5 mapas Bountyforge (asset, trust, identity, state, capability) para el chain-analyst
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:map

Construye los 5 mapas estructurados que `chain-analyst` (y `/quarry:chain`)
usan como insumo. Son el puente entre recon (datos crudos) y hunting
(prueba dirigida): sin mapas, hunting se vuelve ad-hoc y chain-analysis
no tiene con qué trabajar.

## Precondición

- Fase del engagement debe ser `RECON` o posterior, con al menos un
  asset registrado en `coverage.json`. Si `/quarry:recon` no corrió nunca,
  detener y recomendarlo primero — los mapas sin datos de recon son
  especulación, no mapas.
- Leer `asset-inventory.md` y los raw outputs en `<audit_dir>/raw/`
  antes de mapear — no inventar relaciones de confianza o roles que no
  estén respaldados por lo observado.

## Los 5 mapas

Cada uno vive en `skills/mapping/<nombre>/SKILL.md` (metodología) y se
materializa como `<audit_dir>/report/maps/<nombre>.md`.

1. **Asset map** (`asset-map`) — todo lo descubierto en recon,
   normalizado: dominios, subdominios, IPs, puertos/servicios, endpoints
   de API, buckets cloud, repos, apps móviles. Agrupar por "sistema
   lógico" (ej. todo lo que sirve al mismo frontend) no solo por tipo.

2. **Trust map** (`trust-map`) — fronteras de confianza y flujos entre
   assets: qué llama a qué, qué cruza una frontera de confianza (ej.
   frontend público → API interna → base de datos), qué asume
   confianza implícita en un header, IP interna, o token sin validar
   origen. Esto es lo que después alimenta `ssrf`, `cors`,
   `host-header`.

3. **Identity map** (`identity-map`) — modelo de autenticación completo:
   mecanismos (sesión, JWT, OAuth, API key), roles y sus privilegios,
   dónde se emiten y validan los tokens, si hay múltiples tenants y cómo
   se aíslan. Alimenta `auth-bypass`, `jwt`, `oauth`,
   `idor`.

4. **State map** (`state-map`) — qué mantiene estado y dónde: sesiones
   (server-side vs JWT stateless), caches (CDN, app-level, Redis),
   colas, websockets persistentes. Dónde el estado puede ser envenenado
   o leído entre usuarios. Alimenta `cache-poisoning`,
   `race-condition`, `session-management`.

5. **Capability map** (`capability-map`) — qué puede hacer cada
   componente/rol: qué endpoints mutan datos, cuáles son de solo lectura,
   qué acciones son irreversibles o sensibles (pagos, borrado, cambio de
   rol), qué componente tiene qué nivel de privilegio de red/cloud.
   Alimenta `chain-analysis` directamente — "capability" es lo que una
   cadena de findings termina obteniendo.

## Pasos exactos

1. Para cada uno de los 5 mapas, leer su `SKILL.md` en
   `skills/mapping/<nombre>/` si existe; si no está escrito aún, usar la
   definición de arriba y señalarlo como gap de contenido sin bloquear.
2. Construir el mapa en formato tabla + lista de relaciones (no prosa
   libre — el chain-analyst necesita parsear esto).
3. Escribir cada mapa en `<audit_dir>/report/maps/<nombre>.md`.
4. Generar un índice `<audit_dir>/report/maps/README.md` que enlaza los 5
   y resume en 3-5 líneas el hallazgo estructural más relevante de cada
   uno (ej. "trust-map: el servicio de PDF interno confía en IP origen
   sin validar — candidato a SSRF").
5. Transicionar la fase a `MAPPED` si venía de `RECON`
   (`state.transition(Phase.MAPPED)`).

## Edge cases

- **Recon insuficiente para un mapa** (ej. no se hizo cloud-recon, no
  hay datos para capability map de infra cloud): dejar esa sección del
  mapa explícitamente marcada `SIN DATOS — requiere recon adicional`, no
  rellenar con supuestos.
- **Target de una sola página/API simple**: los 5 mapas igual se generan,
  pero pueden ser cortos. No omitir ninguno — incluso un mapa "trivial"
  (ej. identity map = "solo API key estática, sin roles") es información
  útil para chain-analysis.
- **Re-ejecución tras hunting** (se descubrió un asset o rol nuevo
  durante hunting): actualizar el mapa afectado en vez de regenerar todo
  desde cero; anotar qué cambió y por qué en el README de maps.

## Output esperado

- Los 5 archivos de mapa + README de índice, con rutas.
- Lista de "SIN DATOS" si algún mapa quedó incompleto por falta de recon.
- Próximo paso recomendado: `/quarry:hunt` (breadth-first sobre todos los
  assets y clases).
