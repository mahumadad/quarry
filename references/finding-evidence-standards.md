# Finding Evidence Standards

> Qué cuenta como prueba mínima por clase de vulnerabilidad. Un finding sin
> este mínimo no se reporta como `Demonstrated` — baja a `Inferred` o
> `Unproven` según `anti-fabrication-rules.md`.

## Principio general

La evidencia debe permitir que un tercero, sin acceso al target ni al
operador, confirme que la vulnerabilidad existe únicamente leyendo el
finding. Esto significa: request completo (incluyendo headers relevantes
como auth), response completo (o el fragmento que demuestra el efecto), y
el contexto necesario para interpretarlo.

## Estándares por clase de vulnerabilidad

### SQL Injection (SQLi)

**Mínimo:** query inyectada + evidencia del efecto en la base de datos
(dato extraído que no debería ser accesible, error de sintaxis SQL
reflejado que confirma construcción dinámica de la query, o diferencia de
timing/boolean consistente y reproducible mínimo 3 veces).
**Ideal:** extracción de un dato verificable (versión de BD, nombre de
tabla no documentada, registro de otro usuario) vía la inyección.
**N/A común:** un error 500 genérico sin mensaje de BD no es evidencia de
SQLi — puede ser cualquier excepción no manejada. Se reporta como "error
no manejado" hasta confirmar la causa SQL específica.

### XSS (reflejado/almacenado/DOM)

**Mínimo:** screenshot o grabación del efecto en el navegador (alert,
cambio de DOM visible, ejecución de JS confirmada vía `console.log`
observado) + el payload exacto + el punto de inyección (parámetro/campo).
**Ideal:** demostrar impacto más allá del alert — robo de cookie/token no
HttpOnly, acción ejecutada en nombre de la víctima (CSRF-like vía XSS).
**N/A común:** reflejo del payload en el HTML fuente sin ejecución
confirmada (ej. dentro de un atributo con encoding que neutraliza el
contexto) no es XSS — es "reflejo sin ejecución", severidad informativa.

### SSRF

**Mínimo:** si hay respuesta visible, el contenido de la respuesta del
recurso interno solicitado. Si es blind, un callback OOB recibido
(interactsh/Collaborator) con timestamp correlacionado al request enviado.
**Ideal:** acceso confirmado a un recurso interno no accesible públicamente
(metadata endpoint, servicio interno, puerto no expuesto).
**N/A común:** timeout o error de conexión al pedir una URL interna no es
evidencia de SSRF sin un callback OOB — puede ser simplemente que el
request nunca salió del contexto esperado (validación de URL funcionando).

### IDOR / Broken Access Control

**Mínimo:** dos requests — uno con la identidad A accediendo al objeto de
la identidad B, mostrando el ID/parámetro modificado y la response con
datos de B. Debe quedar claro que A no tenía permiso legítimo sobre ese
objeto.
**Ideal:** demostrar el patrón en más de un objeto/ID para descartar que
fue un caso aislado de configuración de ese objeto específico.
**N/A común:** acceder a un recurso con un ID secuencial que resulta ser
público por diseño (ej. contenido marcado explícitamente como público) no
es IDOR.

### CSRF

**Mínimo:** PoC HTML/JS que ejecuta la acción estando la víctima
autenticada en otra pestaña, sin interacción adicional más allá de abrir
la página maliciosa, + confirmación de que la acción se ejecutó (cambio de
estado observado en la cuenta víctima).
**N/A común:** una acción que ya requiere un token anti-CSRF válido
obtenido por otro medio no cuenta como CSRF solo porque el header
`Origin`/`Referer` no se valida — hay que demostrar la cadena completa.

### RCE / Command Injection

**Mínimo:** output de un comando no destructivo ejecutado en el target
(ej. `id`, `whoami`, `hostname`) capturado en la response o vía
out-of-band.
**Ideal:** cuando las reglas de engagement lo permiten, screenshot de una
shell interactiva o archivo de prueba (marcador único, no destructivo)
escrito y leído de vuelta.
**N/A común:** un comando que tarda más de lo esperado no es evidencia de
ejecución sin confirmar el output — puede ser timeout de red.

### SSTI (Server-Side Template Injection)

**Mínimo:** payload matemático (ej. expresión que el motor de templates
evalúa) con el resultado evaluado visible en la response, confirmando
ejecución del motor de templates y no solo reflejo de texto.
**Ideal:** escalar de evaluación matemática a ejecución de comando/lectura
de archivo cuando el engine lo permite.

### XXE

**Mínimo:** si hay respuesta visible, contenido de un archivo local leído
vía la entidad externa. Si es blind, callback OOB recibido.
**N/A común:** un parser que rechaza el DOCTYPE con un error claro no es
vulnerable — confirmar que el error es de sintaxis XML genérica y no de
seguridad antes de descartar, pero no reportar sin la lectura/callback
confirmados.

### Deserialización insegura

**Mínimo:** efecto observable de la deserialización de un objeto/gadget
controlado (ejecución de comando, crash específico distinto a un error de
parsing genérico, o callback OOB).
**N/A común:** un error 500 al enviar un payload de deserialización
modificado no confirma la vulnerabilidad sin aislar la causa exacta.

### Rate limiting ausente / Brute force

**Mínimo:** N requests consecutivos (documentar N y el tiempo total)
contra el mismo endpoint sensible sin bloqueo, lockout, ni captcha,
mostrando que todos retornaron 200/respuesta válida.
**Ideal:** demostrar el impacto combinado (ver `chain-matrix.md` — rate
limit ausente casi nunca es el finding final, es un habilitador de chain).

### Open Redirect

**Mínimo:** request con el parámetro de redirect apuntando a un dominio
externo controlado + response con header `Location` confirmando el
redirect sin validación.
**N/A común:** redirect a un dominio en una allowlist documentada del
cliente no es un hallazgo.

### JWT / Session management

**Mínimo:** token modificado (algoritmo `none`, firma no verificada, claim
alterado) aceptado por el servidor, con la response confirmando que el
servidor actuó según el claim manipulado (ej. acceso con rol elevado).

### Clickjacking

**Mínimo:** PoC HTML con `iframe` cargando la página objetivo, mostrando
ausencia de `X-Frame-Options`/`frame-ancestors` efectivos, + screenshot del
iframe renderizado.

## Reglas transversales de evidencia

- **Timestamp:** toda evidencia incluye cuándo se generó. Sin timestamp,
  no es verificable como reciente ni reproducible en el tiempo.
- **Anonimización consistente:** si se comparten ejemplos fuera del
  reporte formal (ej. para memoria/reuso de técnicas), anonimizar target
  real (`{{target_domain}}`, `{{target_ip}}`) pero preservar la estructura
  técnica completa.
- **Reproducibilidad por terceros:** si el finding depende de un estado
  transitorio (ej. una condición de carrera), documentar cuántos intentos
  fueron necesarios y la tasa de éxito observada, no solo "funcionó una
  vez".
- **Herramienta vs. verificación manual:** el output de un scanner
  (nuclei, sqlmap, burp scanner) es un *lead*, no evidencia final. Todo
  finding reportado requiere al menos una verificación manual que
  reproduzca el resultado fuera del scanner.

## Escenarios comunes de N/A

- Comportamiento documentado explícitamente como "by design" por el
  cliente en el scope/reglas de engagement.
- Vulnerabilidad que requiere acceso físico o a infraestructura interna
  fuera del scope autorizado.
- Hallazgo que solo se manifiesta en una versión/entorno distinto al que
  está en scope (ej. se reprodujo en staging pero prod tiene un parche
  distinto — se documenta el delta, no se reporta como si aplicara a prod).
- Falso positivo de scanner no confirmado manualmente — se documenta en
  Gaps como "lead sin confirmar" si no hubo tiempo de verificar, nunca como
  finding.
