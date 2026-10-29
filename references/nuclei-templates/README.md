# Templates Nuclei revisados

Catálogo local de checks atómicos para reconocimiento autorizado. La unidad de selección no es “ejecutar todo el framework”, sino **stack + protocolo + arquitectura + autenticación + riesgo**.

## Contrato de ejecución

- Índice hash-locked: `references/nuclei-manifest.json`, fuera de la carpeta que recibe Nuclei.
- Selector: `engine/nuclei_templates.py` sobre `AppProfile`.
- Runner: `engine/nuclei_runner.py`, con scope, ventana, aprobaciones, `-dr`, `-ni`, límites y JSONL.
- Evidencia: `ArtifactStore` y `.pentest-state/nuclei-coverage.json`.
- Todo match es un **lead**, no un finding. Cero matches no demuestra ausencia.
- Community no forma parte del catálogo revisado. Se revisa y fija por versión de forma puntual; no se ejecuta en bulk ni se actualiza ciegamente.

```bash
# Validar política, hashes y estructura local
python -m engine.nuclei_templates validate

# Revisar selección sin tocar el target
python -m engine.nuclei_runner --audit-dir <audit> --target https://target.example \
  --run-id <run> --plan-only

# Ejecutar solo checks safe seleccionados por AppProfile
python -m engine.nuclei_runner --audit-dir <audit> --target https://target.example \
  --run-id <run> --risk safe

# Después de revisar conscientemente un cambio de templates
python -m engine.nuclei_templates refresh
nuclei -validate -duc -t references/nuclei-templates/
```

## Cobertura actual: 40 checks

| Familia | Checks | Alcance |
|---|---:|---|
| Python / FastAPI / Django / Flask / Celery | 6 | OpenAPI, admin, debug, secretos y Flower |
| Node / Express / Nest / Next / Nuxt / colas | 8 | Stack traces, secretos, source maps, manifests, devtools, OpenAPI y Bull Board |
| Rails / Sidekiq | 4 | Debug, rutas, secretos y dashboard |
| GraphQL | 3 | Introspection, batching read-only y field suggestions |
| Magento / VTEX | 4 | Superficie admin y APIs públicas sin consultar clientes |
| Fintech / pagos | 4 | OpenAPI, secretos live/test y datos financieros con gate |
| Spring | 3 | Health detallado, mappings y environment con gate |
| Laravel / Horizon | 3 | Ignition, secretos y dashboard |
| ASP.NET | 2 | Developer Exception Page y connection strings |
| Kong / Traefik / Envoy | 3 | Admin/API/gateway; Envoy requiere gate de datos sensibles |

## Niveles de riesgo

- `safe`: GET o GraphQL read-only, sin redirects ni destinos externos.
- `authenticated`: requiere mecanismo e identidad declarados en AppProfile.
- `sensitive-data`: lectura que puede devolver secretos, datos financieros o configuración interna; exige aprobación exacta.
- `state-changing` y `oast`: la política los reconoce para futuros casos revisados, pero el catálogo actual no los incluye.

## Reglas de calidad

Cada YAML debe tener:

1. `reviewed: true`, riesgo, stacks, cobertura y fixture en `info.metadata`.
2. Solo `id`, `info` e `http`; sin code/file/headless/workflow/javascript.
3. Rutas derivadas exclusivamente de `{{BaseURL}}/`, sin otro host, puerto, redirect ni path traversal.
4. Solo GET, salvo GraphQL read-only sin mutations/subscriptions.
5. `matchers-condition: and`, status y contenido específico. HTTP 200 aislado está prohibido.
6. Severidad acorde: admin/docs/API públicas = `info`; exposición esperada no se vende como vulnerabilidad.
7. Positivo, negativo, soft-404/login y evidencia de prueba sin secretos reales.

## Lo que Nuclei no cubre

IDOR, autorización entre roles, lógica de negocio, race conditions, cadenas complejas y validación de webhooks con efectos siguen en skills manuales/browser. gRPC, WebSocket y serverless interno requieren técnicas específicas; no se declara cobertura genérica inexistente.

Los paths fijos de bundles son solo un pase mínimo. El crawl y `js-analysis` deben analizar los assets realmente descubiertos; no asumir que `main.js` agota la cobertura.
