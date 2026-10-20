# Chain Matrix

> Tabla de combinaciones conocidas: Finding A + Finding B → resultado de la
> cadena + severidad combinada. Esta matriz es el lookup principal de
> `engine/chain_engine.py` en modo matriz — antes de buscar cadenas
> ad-hoc, verificar si la combinación observada ya coincide con un patrón
> catalogado acá.
>
> La severidad combinada es una guía de punto de partida, no un resultado
> automático — siempre se ajusta con la justificación métrica real en
> `chain-report.md` (ver Combined CVSS).

## Matriz general

| # | Finding A | Finding B | Cadena resultante | Severidad combinada |
|---|---|---|---|---|
| 1 | IDOR (lectura de objeto ajeno) | Falta de rate limiting | Mass data exfiltration (enumeración completa) | Critical |
| 2 | XSS (almacenado) | CSRF (sin token / SameSite laxo) | Account takeover sin interacción adicional de la víctima | Critical |
| 3 | SSRF (blind o visible) | Cloud metadata endpoint accesible | Robo de credenciales IAM/service account | Critical |
| 4 | Information disclosure (stack trace / debug endpoint) | Auth bypass parcial | Escalada de privilegios | High |
| 5 | Open redirect | OAuth misconfiguration (redirect_uri laxo) | Robo de authorization code / token | High |
| 6 | SQLi (blind) | Ausencia de WAF/rate limit | Dump completo de base de datos | Critical |
| 7 | File upload sin validación de tipo | Path traversal en el serving de archivos | RCE vía webshell | Critical |
| 8 | JWT `alg: none` o clave débil | IDOR en endpoint que confía en claims del JWT | Impersonación de administrador | Critical |
| 9 | Subdomain takeover | Cookie con `Domain` amplio (ej. `.example.com`) | Robo de sesión cross-subdomain | High |
| 10 | CORS mal configurado (`Access-Control-Allow-Origin: *` + credentials) | Endpoint autenticado con datos sensibles | Exfiltración de datos de sesión activa | High |
| 11 | Password reset token predecible | Ausencia de rate limit en el endpoint de reset | Account takeover masivo | Critical |
| 12 | SSTI | Filesystem accesible desde el motor de templates | RCE | Critical |
| 13 | XXE | Filesystem local legible | Lectura de archivos sensibles (configs, claves) | High |
| 14 | Host header injection | Password reset que usa el host para el link | Account takeover vía link envenenado | High |
| 15 | GraphQL introspection habilitada | Falta de autorización por campo/resolver | Exposición de schema + acceso a mutations no documentadas | High |
| 16 | Mass assignment | Campo de rol/privilegio en el mismo modelo | Auto-escalada de privilegio (self role-grant) | Critical |
| 17 | Cache poisoning (header no normalizado) | Contenido sensible cacheable | Exposición de datos de un usuario a otros usuarios | High |
| 18 | HTTP request smuggling | Reverse proxy con autenticación en el edge | Bypass de autenticación / request hijacking | Critical |
| 19 | Race condition en flujo de pago/cupón | Ausencia de idempotency key | Abuso financiero (doble canje, saldo negativo) | High |
| 20 | 2FA bypass (endpoint alternativo sin verificación) | Credenciales filtradas (leak previo) | Account takeover completo pese a 2FA habilitado | Critical |
| 21 | Prototype pollution (JS) | Gadget que llega a `eval`/`exec`/template render | RCE en cliente o servidor según superficie | Critical |
| 22 | API key/secret en JS bundle expuesto | Esa key tiene permisos de escritura en servicio tercero | Compromiso de servicio tercero (ej. storage, analytics, email) | High |
| 23 | Email injection (header injection en formulario de contacto) | Servidor de correo sin SPF/DKIM estrictos | Uso del dominio para spoofing/phishing | Medium |
| 24 | Deserialización insegura | Librería con gadget chain conocido disponible en el classpath | RCE | Critical |
| 25 | Business logic flaw (descuento acumulable sin límite) | Ausencia de validación server-side del monto final | Fraude financiero directo | High |
| 26 | Clickjacking | Acción sensible de un solo clic (ej. "eliminar cuenta", "transferir") | Ejecución de acción destructiva sin consentimiento | Medium–High |
| 27 | Subdomain con panel de admin expuesto | Credenciales default o débiles no rotadas | Acceso administrativo completo | Critical |
| 28 | SSRF hacia servicio interno sin auth | Servicio interno expone API de gestión (ej. Docker API, Kubernetes API) | RCE / control del orquestador | Critical |
| 29 | LFI (local file inclusion) | Log poisoning (user-agent/header reflejado en logs incluidos) | RCE vía log poisoning | Critical |
| 30 | Parameter pollution | Lógica de autorización que solo revisa el primer/último valor del parámetro | Bypass de control de acceso | High |
| 31 | Webhook sin verificación de firma | Endpoint de webhook dispara acción de negocio directa | Falsificación de eventos de negocio (ej. "pago confirmado" falso) | High |
| 32 | Insecure direct object reference en export/reporte (ej. PDF por ID) | Sin rate limit + IDs secuenciales | Exfiltración masiva de documentos de otros usuarios | Critical |

## Patrones reales de engagements del operador

Estos patrones ya fueron observados y confirmados en engagements
autorizados propios — se priorizan como hipótesis de chain de alta
probabilidad cuando aparecen findings compatibles en un nuevo target.

| Engagement | Finding A | Finding B | Cadena confirmada |
|---|---|---|---|
| Syncfonía/GS1 México | F2 — IDOR en `/organizations` (expone RFC + PII de personas físicas) | F7 — ausencia de rate limiting | Dump del padrón completo en horas vía enumeración secuencial de IDs |
| Amplifica | Token leak (token de sesión/API expuesto en respuesta o cliente) | Ausencia de invalidación/verificación adicional al reusar el token | Account Takeover (C5) |
| Las Margaritas | CVE-2024-28000 (oracle verificado) | NF nonce leak + form chain | Cadena de compromiso vía explotación del CVE combinada con fuga de nonce que habilita el envío de formularios con autoridad ajena |

## Cómo usar esta matriz

1. Al confirmar un finding nuevo, buscar en esta tabla si alguna fila tiene
   un "Finding A" o "Finding B" compatible con la clase del finding
   confirmado.
2. Si hay match, revisar si el otro lado de la fila también está presente
   (confirmado o con evidencia parcial) en el engagement actual.
3. Si ambos lados están presentes, generar una `chain-report.md` candidata
   y pasarla por el pipeline de validación adversarial antes de reportarla
   como `VALIDATED`.
4. Si la combinación observada no coincide con ninguna fila, documentarla
   como patrón ad-hoc en `chain-patterns.md` si se confirma — la matriz
   crece con cada engagement.
