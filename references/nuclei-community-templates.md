# Nuclei Community Templates — Catálogo de Repos

> Repositorios de templates nuclei de terceros evaluados para integración
> con el plugin. Los de Tier 1 ya están en la configuración de cent
> (`/root/.config/cent/.cent.yaml` dentro del contenedor kali). Los de
> Tier 2 son candidatos a agregar según el engagement.

## Tier 1 — Integrados en cent (siempre disponibles)

| Repo | Stars | Foco |
|---|---|---|
| `projectdiscovery/nuclei-templates` | 13.2k | Oficial: ~7k templates, CVEs, misconfigs, panels, technologies |
| `topscoder/nuclei-wordfence-cve` | — | WordPress CVEs extraídos de Wordfence Intelligence |
| `rxerium/rxerium-templates` | — | Zero-days, CISA KEV, templates recientes |
| `0xAwali/Blind-SSRF` | — | Blind SSRF específicos (callbacks OOB) |

## Tier 2 — Alto valor, agregar a cent según engagement

### coffinxp/nuclei-templates (548 stars)
- **Stacks**: Next.js (CVE-2025-29927, middleware cache bypass), WordPress
  (takeover), PHP (backup file exposure), AWS (S3 buckets, secrets),
  GraphQL (GET query), Swagger/OpenAPI exposed
- **Vuln classes**: SSRF, CORS, CRLF, open redirect, SQLi, blind XSS
- **Uso**: engagement con Next.js, WordPress, o APIs con Swagger

### geeknik/the-nuclei-templates (304 stars)
- **Stacks**: Django (secret key exposure), Docker (config/registry
  exposed), CI/CD (CircleCI, Drone), Elasticsearch, Couchbase
- **Vuln classes**: blind XXE, RCE out-of-band, DOM XSS
- **Uso**: engagement con infraestructura Docker/CI o backends Python

### UltimateSec/ultimaste-nuclei-templates (644 stars)
- **Stacks**: enterprise chino — Citrix ADC, Nacos, RocketMQ, Metabase,
  Kingdee ERP, Yongyou CRM, Smartbi, OpenFire, GeoServer, nginx-webui,
  QAX VPN
- **Uso**: engagement contra infraestructura enterprise/middleware

### optiv/mobile-nuclei-templates (439 stars)
- **Categorías**: API keys (regex en código decompilado), Android (checks
  sobre smali code), iOS (IPA descomprimido)
- **Uso**: assessment de apps mobile — correr contra output de apktool

### pikpikcu/nuclei-templates (65 stars)
- **Stacks**: Laravel, Spring Boot, SAP NetWeaver, Liferay, Jenkins,
  Kubernetes, Docker, GitLab, Grafana, Prometheus, CouchDB, Citrix,
  Fortinet, Cisco ASA, BIG-IP, Moodle, Symfony
- **Categorías**: cves, panels, brute-force, dns, tokens, misconfigs
- **Uso**: engagement con stacks Java/PHP enterprise o infra de red

### 0xKayala/Custom-Nuclei-Templates (112 stars)
- **Contenido**: colección masiva (~44k entradas numeradas),
  wappalyzer-mapping para fingerprinting automático
- **Nota**: por el volumen, algunos templates pueden estar duplicados o
  sin mantener. Útil como fallback de búsqueda, no como source primario
  de cent

### CharanRayudu/Custom-Nuclei-Templates (133 stars)
- **Contenido**: ~94+ CVE templates (2005-2019), AEM misconfig, incluye
  sub-repos de mobile y custom templates
- **Uso**: engagement con legacy systems o Adobe AEM

## Tier 3 — Meta-agregadores

### emadshanab/Nuclei-Templates-Collection (1.2k stars)
- Script `bulk_clone_repos.py` + `remove_duplicated_templates.py`
- Agrega 100+ repos de templates de investigadores individuales
- **Uso**: para descubrir nuevos repos de templates, no como source
  directa de cent (demasiado ruido). Correr el script, filtrar, evaluar

## Tier 4 — Bulk no verificado (usar con precaución)

### linuxadi/40k-nuclei-templates (355 stars)
- Colección bulk de ~40k templates de múltiples fuentes
- **⚠ Warning**: contenido no verificado individualmente, puede incluir
  templates malformados o con falsos positivos altos
- **Uso**: solo para búsqueda puntual de templates para un CVE o
  tecnología específica. Nunca como source completo de cent

## Nuestros templates custom

En `references/nuclei-templates/` del plugin:

| Template | Target |
|---|---|
| `magento-admin-exposed.yaml` | Panel admin Magento 2 |
| `magento-api-exposed.yaml` | REST/GraphQL API Magento 2 |
| `vtex-admin-panel.yaml` | Admin panel VTEX |
| `vtex-api-exposed.yaml` | APIs VTEX (checkout, catalog, OMS) |
| `graphql-introspection.yaml` | Introspección GraphQL habilitada |
| `graphql-batch-query.yaml` | Batching de queries GraphQL |
| `graphql-field-suggestions.yaml` | Field suggestions activas |

## Gaps sin cobertura dedicada

Estas tecnologías no tienen repos community dedicados, pero ahora tienen
**templates custom** en `references/nuclei-templates/`:

- **Ruby on Rails**: `rails-misconfig.yaml` (debug, rutas, Sidekiq, config)
- **Node.js / Express**: `node-express-misconfig.yaml` (source maps, .env,
  package.json, GraphQL playground). Next.js parcial en coffinxp
- **Python / FastAPI / Django**: `python-fastapi-misconfig.yaml` (auto-docs,
  debug mode, Werkzeug, Celery Flower)
- **Fintech / APIs financieras**: `fintech-api-exposed.yaml` (accounts,
  transactions, portfolios, swagger)
- **Payment gateways** (Stripe, MercadoPago, Transbank):
  `payment-gateway-misconfig.yaml` (keys en JS, webhooks sin firma)
- **E-commerce** más allá de nuestros custom: WooCommerce parcial via
  wordfence, Shopify sin cobertura
- **Latin American platforms** (VTEX deep, Jumpseller, Tiendanube): solo
  nuestros custom

Para gaps restantes, el approach es:
1. Escribir templates custom adicionales según el engagement lo requiera
2. Usar `clairvoyance` + `graphw00f` para GraphQL en vez de nuclei
3. Para Shopify/Jumpseller, combinar fingerprinting genérico (nuclei
   official) + checks manuales del skill correspondiente

## Cómo agregar un repo a cent

En el contenedor kali, editar `/root/.config/cent/.cent.yaml`:

```yaml
community-templates:
  - github.com/projectdiscovery/nuclei-templates
  - github.com/topscoder/nuclei-wordfence-cve
  - github.com/rxerium/rxerium-templates
  - github.com/0xAwali/Blind-SSRF
  # agregar según engagement:
  - github.com/coffinxp/nuclei-templates       # Next.js, WordPress, AWS
  - github.com/geeknik/the-nuclei-templates     # Django, Docker, CI/CD
```

Luego:
```bash
cent -p /root/nuclei-templates/community/ -t
```
