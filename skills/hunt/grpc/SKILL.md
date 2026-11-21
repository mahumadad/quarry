---
name: grpc
description: >
  Test gRPC services: reflection enumeration, plaintext/TLS downgrade, auth in metadata,
  message-level authorization gaps, and known-method fuzzing. Use when recon finds an
  HTTP/2 service speaking gRPC (content-type application/grpc, :status trailers,
  grpc-web proxies) or a mobile/microservices backend with protobuf APIs.
  Keywords: grpc, protobuf, grpcurl, reflection, grpc-web, HTTP/2, metadata auth,
  server reflection, protoset, microservices.
  Do NOT use for plain REST/JSON APIs (use api-abuse) or GraphQL (use graphql).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-306, CWE-862, CWE-319]
  mitre_attack: [T1190, T1040]
  tools: [grpcurl, grpcui, protoc, nuclei]
depends_on: [port-scan, service-enumeration, api-discovery]
feeds_into: [finding-validation, chain-analysis]
chains_with: [idor, auth-bypass, info-disclosure, rce]
---

## Signals

- Port serving HTTP/2 with `content-type: application/grpc` responses, or
  h2c (cleartext HTTP/2) on internal-exposed ports (8080, 50051 typical).
- `application/grpc-web` endpoints on the main web app (browser clients via a
  proxy — often with DIFFERENT auth handling than native gRPC).
- Mobile app or SPA shipping `.proto`-derived clients; protobuf wire format
  visible in proxied traffic.
- Microservices architecture from app-profile — internal gRPC services
  sometimes surface through misconfigured ingress/gateways.

## Methodology

1. **Enumerate via server reflection (the jackpot):**
   ```bash
   grpcurl -plaintext target:50051 list
   grpcurl -plaintext target:50051 list package.ServiceName
   grpcurl -plaintext target:50051 describe package.ServiceName.Method
   ```
   Reflection enabled in production = full API schema disclosure (finding on
   its own, info/low) AND the map for everything below.

2. **No reflection → reconstruct the schema.** Pull protos from: mobile app
   decompilation, public GitHub (github-dorking skill), grpc-web JS bundles,
   or guess well-known service names (health checks `grpc.health.v1`,
   common CRUD naming). Build a protoset:
   ```bash
   protoc --descriptor_set_out=api.protoset --include_imports api.proto
   grpcurl -protoset api.protoset -plaintext target:50051 list
   ```

3. **Transport security:** test plaintext acceptance on TLS-expecting ports
   and h2c exposure. Cleartext gRPC carrying auth tokens = CWE-319.

4. **Auth in metadata, not messages.** gRPC auth rides in metadata headers:
   ```bash
   grpcurl -H "authorization: Bearer TOKEN" -plaintext target:50051 \
     package.Service/Method -d '{"id": "1"}'
   ```
   Test: (a) no metadata at all — many internal-trust services answer
   unauthenticated; (b) expired/foreign token; (c) token from a different
   service/audience (confused-deputy between microservices).

5. **Message-level authorization (the gRPC IDOR).** AuthN happens at the
   metadata layer; object-level checks live in handler code and are often
   missing because "the gateway checks that". Swap object IDs in message
   fields using the session-context discipline (same call as user_a/user_b):
   ```bash
   grpcurl -H "authorization: Bearer USER_B_TOKEN" target:443 \
     billing.Billing/GetInvoice -d '{"invoice_id": "USER_A_INVOICE"}'
   ```

6. **Input validation on scalar/bytes fields:** protobuf is typed, but string
   and bytes fields carry the same injection classes as REST — SQLi, SSTI,
   command injection, oversized messages (decompression bombs with
   grpc-encoding gzip). Route through the relevant hunt skill on a hit.

7. **grpc-web divergence:** if the app exposes BOTH grpc-web (browser) and
   native gRPC (partners/internal), diff their auth and rate-limit behavior —
   proxies frequently normalize differently and one path skips checks.

## Tooling

- `grpcurl` — the core client (reflection, protoset, custom metadata).
- `grpcui` — interactive exploration once a protoset exists.
- `protoc --descriptor_set_out` — build protosets from recovered .proto files.
- `nuclei -tags grpc` — quick exposure/misconfig triage.

## Payloads & Detection Patterns

Guía de caza: una familia por capa de la pila gRPC (transporte, metadata/authN, mensaje/authZ,
campos escalares). authN vive en metadata; authZ de objeto vive en el handler y suele faltar.

| Categoría | Shape | Propósito |
|---|---|---|
| Reflection enum | `grpcurl -plaintext t:50051 list` / `describe` | Disclosure del esquema completo |
| No-auth probe | call sin metadata `authorization` | Servicios internal-trust que responden sin auth |
| Token confusion | token expirado / de otro service / otra audience | Confused-deputy entre microservicios |
| Message-level IDOR | swap `{"id":"OTHER_TENANT"}` con token propio | authZ ausente a nivel objeto |
| Transport downgrade | `-plaintext` en puerto TLS-expecting, h2c | CWE-319: token/datos en claro |
| Scalar injection | SQLi/SSTI/cmd en campos `string`/`bytes` del `-d` | Mismas clases que REST sobre protobuf |
| Decompression bomb | `grpc-encoding: gzip` con mensaje enorme | DoS por descompresión |
| grpc-web divergence | mismo método vía grpc-web vs nativo | Un path salta auth/rate-limit |

Surface signals que delatan la clase antes de probar:
- `content-type: application/grpc` sobre HTTP/2, o h2c (cleartext) en 8080/50051.
- Endpoints `application/grpc-web` en la web app (auth distinta a la nativa).
- Reflection habilitada (`list` devuelve servicios) → mapa completo + finding info/low por sí solo.
- App móvil/SPA con clientes `.proto` → esquema reconstruible aunque no haya reflection.

```bash
grpcurl -plaintext target:50051 list                          # reflection → disclosure de esquema
grpcurl -plaintext target:50051 describe package.Svc.Method   # firma del mensaje
# IDOR de objeto: identidad propia, objeto ajeno (diff session-context user_a/user_b)
grpcurl -H "authorization: Bearer USER_B" target:443 \
  billing.Billing/GetInvoice -d '{"invoice_id":"USER_A_INV"}'
```

```bash
# no-auth y downgrade de transporte
grpcurl -plaintext target:50051 package.Svc/Method -d '{"id":"1"}'   # sin metadata = ¿responde?
grpcurl -plaintext target:443   package.Svc/Method -d '{"id":"1"}'   # plaintext en puerto TLS = CWE-319
```

Vector ciego (inyección en campo `string`/`bytes` que gatilla fetch o exec server-side): incrusta
el `payload_url` de un token OAST (`engine.oast`) en el `-d` y correlaciona el callback para llegar
a `Demonstrated`; sin hit, queda **Inferred**.

## Bypass Techniques

Agrupadas por la defensa que evaden; probar la familia completa antes de declarar no-vulnerable.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Auth "ya validada" en gateway | Golpear el servicio gRPC directo (ingress mal config) | El handler confía en el gateway y no revalida objeto |
| Reflection deshabilitada | Reconstruir protoset (mobile decompile, grpc-web JS, GitHub) | `protoc --descriptor_set_out` → protoset |
| TLS esperado | `-plaintext` / upgrade h2c | Algún LB acepta cleartext en el tramo interno |
| Validación en el proxy grpc-web | Usar el canal gRPC nativo (o viceversa) | Normalización divergente salta checks |
| Rate-limit por método | Variar método/streaming, distribuir carga | Los límites suelen ser por-endpoint |
| Tipado protobuf "seguro" | Inyectar en campos `string`/`bytes` | El tipo no sanea el contenido del campo |

## Validation Gate (minimum proof)

- **Schema disclosure:** `list`/`describe` output captured from the live
  service (not from repo files alone).
- **Missing authN:** a successful response to a call that per app-profile
  requires authentication, with the exact `-d` message and absent metadata
  documented.
- **Missing authZ (IDOR):** identity-swapped call returning another tenant's
  object — session-context diff evidence applies.
- **Cleartext:** successful `-plaintext` call carrying real data on a port
  reachable from the tested network position.

## Gotchas

- **Reflection absent ≠ secure.** State it as schema-not-enumerated (a
  coverage gap), never as "not vulnerable".
- **Health service responding** (`grpc.health.v1.Health/Check`) is normal —
  note it, don't report it as exposure unless it leaks service internals.
- **Load balancers terminate HTTP/2 badly:** some LBs downgrade or strip
  trailers — a flaky grpcurl may be infra, not the app. Retry with
  `-v` and note transport behavior in evidence.
- **Streaming methods** need explicit message counts in grpcurl (`-d` per
  message); a hanging stream is not a crash — set deadlines.
- Internal gRPC exposed via **misconfigured ingress** is in scope only if the
  endpoint is reachable from your authorized network position — check scope
  before deep testing of an internal service surfaced by accident.

## Chain Anchors

1. Unauthenticated gRPC → enumerate ALL services/methods via reflection →
   map which mutate state (operator gate before invoking).
2. Metadata-confusion possible → test cross-service token reuse for lateral
   movement between microservices (chain-multi-app).
3. Injection in a string field → hand to sqli/rce with the working
   gRPC transport as the delivery mechanism (payload via `-d`).
4. Cleartext/h2c transport carrying tokens → capture a live token off the wire
   and test replay against other services (feeds auth-bypass/chain-analysis).

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.
