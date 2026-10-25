# Custom Nuclei Templates

Templates propios para plataformas que **no tienen cobertura** en los repos community.

## Inventario

| Template | Plataforma | Severidad | Qué detecta |
|---|---|---|---|
| `magento-admin-exposed.yaml` | Magento 2 | low | Panel admin accesible (/admin, /backend, variantes) |
| `magento-api-exposed.yaml` | Magento 2 | medium | REST API sin autenticación (storeConfigs, countries, currency, websites) |
| `vtex-admin-panel.yaml` | VTEX | low | Panel admin / VTEX ID login expuesto |
| `vtex-api-exposed.yaml` | VTEX | medium | APIs públicas (catalog, checkout, Master Data, sessions, IO) |
| `graphql-introspection.yaml` | GraphQL | medium | Introspection habilitada → schema completo |
| `graphql-batch-query.yaml` | GraphQL | medium | Batch queries aceptadas → DoS / brute force / rate-limit bypass |
| `graphql-field-suggestions.yaml` | GraphQL | low | Sugerencias de campos en errores → enum sin introspection |
| `fintech-api-exposed.yaml` | Fintech | medium | APIs financieras expuestas (accounts, transactions, portfolios, docs) |
| `payment-gateway-misconfig.yaml` | Payment | high | Keys de Stripe/MercadoPago/Transbank en JS, webhooks sin firma |
| `rails-misconfig.yaml` | Rails | medium | Debug mode, rutas expuestas, Sidekiq, config leaks |
| `node-express-misconfig.yaml` | Node/Express | medium | Source maps, package.json, .env, GraphQL playground |
| `python-fastapi-misconfig.yaml` | Python | medium | FastAPI docs, Django debug, Flask Werkzeug, Celery Flower |

## Uso

### Con cent (dentro del contenedor kali)

cent descarga automáticamente los repos community al primer arranque. Para agregar
estos templates custom al path de nuclei:

```bash
# Copiar templates custom al directorio de nuclei
cp /ruta/a/estos/templates/*.yaml /root/nuclei-templates/custom/

# Correr nuclei con templates custom + community
nuclei -u https://target.com -t /root/nuclei-templates/custom/ -t /root/nuclei-templates/community/
```

### Directamente con nuclei

```bash
# Un template específico
nuclei -u https://target.com -t graphql-introspection.yaml

# Todos los custom de una plataforma
nuclei -u https://target.com -t /path/to/templates/ -tags vtex

# Filtrar por severidad
nuclei -u https://target.com -t /path/to/templates/ -severity medium,high
```

### Tags disponibles

- `magento` — templates de Magento 2
- `vtex` — templates de VTEX
- `graphql` — templates de GraphQL
- `api` — detección de APIs expuestas
- `ecommerce` — todas las de e-commerce (magento + vtex)
- `fintech` — APIs y endpoints financieros
- `payment` — payment gateways (Stripe, MercadoPago, Transbank)
- `rails` — Ruby on Rails
- `nodejs` / `express` — Node.js / Express
- `python` / `fastapi` / `django` / `flask` — Python frameworks

## Repos community (vía cent)

El archivo `/root/.config/cent/.cent.yaml` en el contenedor kali incluye:

| Repo | Qué aporta |
|---|---|
| `projectdiscovery/nuclei-templates` | Repo oficial (~8k templates) |
| `topscoder/nuclei-wordfence-cve` | CVEs de WordPress (Wordfence feed) |
| `rxerium/rxerium-templates` | Templates community verificados |
| `0xAwali/Blind-SSRF` | Detección de Blind SSRF |

## Nota de seguridad

Requiere **nuclei ≥ 3.8.0** por:
- GHSA-29rg-wmcw-hpf4 — leak de JS en templates
- GHSA-jm34-66cf-qpvr — RCE por expression injection desde templates maliciosos

Nunca correr templates de fuentes no verificadas sin revisión previa.
