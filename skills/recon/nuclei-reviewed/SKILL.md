---
name: nuclei-reviewed
description: Ejecuta checks Nuclei custom revisados y seleccionados por AppProfile, con scope fail-closed, riesgo explícito, hashes y evidencia JSONL. Úsalo tras fingerprinting web/API y antes de hunting; no para ejecutar carpetas community ni sustituir validación manual.
---

# Nuclei revisado y seleccionado por perfil

## Contrato

- Usar `engine/nuclei_runner.py`; no lanzar `nuclei -t references/nuclei-templates/` directamente.
- El catálogo `references/nuclei-manifest.json` bloquea YAML nuevo o modificado hasta revisión.
- `safe` es el único perfil predeterminado. `authenticated` requiere identidad en AppProfile.
- `sensitive-data`, `state-changing` y `oast` requieren aprobación exacta del operador. El catálogo actual no autoriza state-changing ni OAST.
- Nuclei produce leads. Nunca promover un match a finding sin reproducción independiente e impacto.
- Cero matches significa “checks ejecutados sin leads”, nunca “target limpio”.

## Flujo

1. Confirmar scope, ventana y engagement activo.
2. Construir o actualizar `AppProfile` antes de seleccionar:
   - `tech_stack.frameworks`, frontend y backend con evidencia.
   - `api.style` y entry points GraphQL descubiertos.
   - `architecture.style`, deployment, rendering, gateway y workers cuando estén confirmados.
   - `payment_processing=true` solo con evidencia de pagos.
   - No inventar arquitectura para desbloquear templates; lo desconocido queda como gap.
3. Ejecutar primero `--plan-only` con `NucleiRunner`. Revisar seleccionados, omitidos y gaps.
4. Ejecutar el perfil `safe` con rate limit conservador. Bajar a `-rl 1 -c 1` en proxies frágiles.
5. Persistir JSONL, cobertura, engine/versión, IDs y hashes mediante `ArtifactStore`.
6. Revisar leads sin exponer secretos en el chat; las vistas redactadas son para análisis y reporte.
7. Si un stack o arquitectura no tiene template revisado, registrar `no_reviewed_custom_template`; usar community solo tras revisión puntual o continuar con el skill manual.

## Selección y arquitectura

La coincidencia de stack es obligatoria. Los checks con arquitectura específica además exigen evidencia de `monolith`, `microservices`, `spa`, `ssr`, `api-gateway` o `kubernetes`. No ejecutar todos los templates ante stack desconocido.

Los endpoints descubiertos tienen prioridad sobre rutas genéricas. Si una aplicación monta GraphQL o OpenAPI en una ruta no convencional, agregar ese entry point al mapa y usar los skills HTTP/GraphQL; no ampliar indiscriminadamente wordlists.

## Límites deliberados

- Sin redirects, raw requests, código, file, headless, JavaScript, OAST ni destinos que cambien host o puerto.
- Sin POST a webhooks, mutaciones GraphQL, uploads, login, fuerza bruta o cambios de colas.
- IDOR, autorización entre roles, lógica de negocio, race conditions y cadenas requieren skills manuales/browser.
- Webhooks sin firma se validan solo en staging o con una prueba específicamente autorizada; HTTP 200/`ok` no demuestra ausencia de firma.
- gRPC reflection, WebSocket y serverless interno no tienen un check HTTP genérico: usar herramientas y rutas específicas.

## Salida mínima

- Estado de ejecución y backend/versión.
- Templates ejecutados y omitidos con razón.
- Gaps de stack/arquitectura y cobertura no aplicable.
- Leads deduplicados por template/target, pendientes de validación.
- Ruta de artefactos JSONL y `nuclei-coverage.json`.
