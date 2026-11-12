---
name: graphql
description: >
  Hunt for GraphQL-specific vulnerabilities: introspection exposure, batch query/alias
  abuse for rate-limit bypass, deeply nested query DoS, and authorization bypass at the
  field/resolver level (vs. the endpoint level). Use on any target exposing a `/graphql`
  (or similarly named) endpoint.
  Keywords: GraphQL, introspection query, batching, query depth, field-level authorization,
  resolver, aliasing, IDOR via GraphQL, InQL, graphql-voyager, DoS via nested query.
  Do NOT use for generic REST IDOR (idor covers that pattern on REST) or generic rate
  limiting outside GraphQL batching (rate-limiting) — this skill is specifically about
  the GraphQL query language's own structural features as an attack surface.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-285, CWE-400, CWE-200]
  mitre_attack: [T1190]
  tools: [burpsuite, InQL, graphql-voyager, curl, "graphql-cop"]
depends_on: [active-recon, api-discovery]
feeds_into: [chain-analysis, idor]
chains_with: [idor, broken-access-control, rate-limiting]
---

## Signals

- Any endpoint named/behaving like `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`,
  or a POST-only JSON endpoint whose body accepts `{"query": "..."}`.
- Introspection enabled: a standard `__schema` query returns the full type/field graph
  instead of an error.
- A GraphiQL/Playground/Apollo Sandbox UI reachable without authentication.
- Mutations and queries that mirror REST endpoints you've already mapped — a strong signal
  that the same authorization logic may (or may not) have been re-implemented per-resolver,
  which is where field-level bypass tends to live.
- Responses that include fields you didn't explicitly request authorization for, when the
  schema exposes relationship fields (e.g., a `user` type exposing a `payments` field
  resolvable from any authenticated session regardless of ownership).

## Prerequisites

- At least one authenticated test account; two accounts with different privilege levels or
  owning different resources is strongly preferred for the authorization tests in step 4.
- The schema (via introspection if enabled, or reconstructed manually from observed queries
  if disabled) before attempting field-level tests — you need to know what fields/types
  exist to target them meaningfully.

## Methodology

1. **Introspection check.** Send the standard introspection query and record whether it
   succeeds:
   ```bash
   curl -s -X POST https://target/graphql -H "Content-Type: application/json" \
     -d '{"query":"query IntrospectionQuery { __schema { queryType { name } types { name kind fields { name } } } } "}'
   ```
   If it succeeds, export the full schema and load it into **graphql-voyager** (schema
   visualization) and Burp's **InQL** extension (which also auto-generates a query
   template library from the schema) to map every type, field, and mutation before testing
   further.

2. **Schema reconstruction if introspection is disabled.** Collect real queries from
   `js-analysis`/traffic capture and rebuild a partial schema manually, or use
   `graphql-cop`'s field-suggestion/error-message-based reconstruction (many servers leak
   field names in "did you mean" error messages even with introspection off) — note this is
   a weaker starting point and schema coverage will be incomplete.

3. **Batch/alias abuse for rate-limit and brute-force bypass.** Test whether the endpoint
   allows multiple aliased operations in a single request, which can bypass per-request
   rate limiting that only counts HTTP requests, not logical operations inside one:
   ```bash
   curl -s -X POST https://target/graphql -H "Content-Type: application/json" \
     -d '{"query":"query { a: login(user:\"test\",pass:\"guess1\"){token} b: login(user:\"test\",pass:\"guess2\"){token} }"}'
   ```
   Confirm by comparing how many underlying attempts register against the app's rate-limit
   counter vs. how many logical operations you sent — a counter that only increments once
   per HTTP request is the vulnerable behavior.

4. **Deep-nesting / query-complexity DoS probe (low-intensity confirmation only).** Submit
   a query with a small number of nested levels first and measure response time/resource
   signals before scaling up, to avoid an accidental denial of service against the target
   without an explicit destructive-action gate:
   ```bash
   curl -s -w "\ntime_total: %{time_total}\n" -X POST https://target/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"query { a { b { c { name } } } }"}'
   ```
   Escalate nesting depth incrementally only while response time scales roughly linearly;
   stop and report as Inferred (no query-depth/complexity limit observed) rather than
   pushing to the point of an actual outage — DoS confirmation is a destructive action
   requiring operator sign-off per project rules.

5. **Field-level authorization bypass.** With two accounts of different privilege/ownership,
   request a field on a resource owned by account B while authenticated as account A,
   using the exact field names mapped in step 1–2:
   ```bash
   curl -s -X POST https://target/graphql -H "Authorization: Bearer $TOKEN_A" \
     -H "Content-Type: application/json" \
     -d '{"query":"query { user(id: \"<account_B_id>\") { email paymentMethods { last4 } } }"}'
   ```
   Compare against the equivalent REST endpoint's authorization (if one exists) for the
   same data — a mismatch (REST blocks it, GraphQL resolver doesn't) is the core finding
   this skill targets.

6. **Mutation-side authorization check.** Repeat step 5 against mutations (not just
   queries) — write-path authorization is frequently missed where read-path checks were
   actually implemented:
   ```bash
   curl -s -X POST https://target/graphql -H "Authorization: Bearer $TOKEN_A" \
     -H "Content-Type: application/json" \
     -d '{"query":"mutation { updateUser(id: \"<account_B_id>\", input: {bio: \"test\"}) { id } }"}'
   ```

7. **Type confusion / input coercion check.** Where a field accepts a union or interface
   type, test whether supplying an unexpected concrete type bypasses validation scoped to
   the expected type (e.g., an authorization check written against one implementing type
   but not enforced against a sibling type implementing the same interface).

## Tooling

- **InQL** (Burp extension) — schema-driven query template generation and systematic field
  enumeration once introspection is available.
- **graphql-voyager** — visual schema explorer; useful for spotting relationship fields that
  cross ownership boundaries (the fields most likely to carry a field-level auth gap).
- **graphql-cop** — automated checks for common GraphQL misconfigurations (introspection
  exposure, batching, missing depth/complexity limiting, field suggestion leakage).

## Root Causes

- Authorization implemented at the HTTP/endpoint layer for REST but not re-implemented per
  resolver when the same data was exposed through GraphQL.
- No query cost/complexity analysis or depth limiting configured on the GraphQL server,
  so arbitrarily nested/aliased queries consume unbounded resources.
- Introspection left enabled in production, handing an attacker the full data model without
  any enumeration effort.
- Rate limiting implemented by counting HTTP requests rather than logical operations,
  trivially bypassed by batching/aliasing.

## Validation Gate (minimum proof)

- Minimum: **actual data access or a demonstrated behavior deviation**, not just a
  structural observation. "Introspection is enabled" alone is Inferred/informational; it
  becomes a reportable finding only combined with what introspection actually revealed that
  shouldn't be public, or when it's used to find the field-level bypass in step 5.
- For authorization bypass: the exact query and response showing account A received data
  or performed a mutation scoped to account B, with both accounts' identities and the
  request/response pair documented.
- For batching/rate-limit bypass: a side-by-side comparison showing N logical operations
  processed against a rate-limit counter that incremented fewer than N times.
- For DoS: documented response-time scaling trend (Inferred) — do not escalate to an actual
  outage without explicit operator authorization for a destructive test.

## Gotchas

- **Overclaim trap:** introspection being enabled is not itself a vulnerability on many
  modern stacks (lots of public APIs intentionally expose it) — the finding is what it
  reveals (internal-only types/fields/mutations not meant for the current consumer) or what
  it enables you to find downstream, not the exposure in isolation.
- **Common N/A:** a persisted-queries-only setup (client sends a query ID, not a raw query
  string) defeats most of steps 3–6 as written — confirm whether arbitrary queries are
  actually accepted before building a whole test plan on introspected schema data.
- **Common N/A:** per-field complexity scoring/depth limiting actually enforced (test
  returns a specific "query too complex" error rather than succeeding) — verify the limit
  is real by finding the actual threshold, not just assuming because one deep query was
  rejected.
- **Overclaim trap:** a field-level bypass that only returns data the requesting user is
  also entitled to see through a different, authorized path is not a vulnerability — confirm
  the data genuinely belongs to a different principal with no sharing relationship.
- Batch/alias requests can look identical to legitimate complex client queries in logs —
  document the exact query sent so the finding is unambiguous to a reviewer.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Introspection to full schema abuse** — Does introspection exposure reveal mutations/fields not used by the official client, widening the attack surface?
2. **Batching/aliasing for auth bypass** — Can query batching or aliasing brute-force rate-limited fields (login, OTP) past per-request limits?
3. **Nested query DoS** — Can a deeply nested or circular query cause resource exhaustion when query complexity/depth isn't limited?
4. **IDOR via object-level auth gaps** — Do individual resolvers enforce object-level authorization, or can other users' data be fetched by ID through a different query/mutation path?
5. **Error-based information disclosure** — Do verbose GraphQL errors leak schema internals, stack traces, or validation details useful for further attack?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Field-level authorization bypass exposing another user's data → feeds **idor** /
  **broken-access-control** for the broader cross-account access-control assessment.
- Batching bypassing rate limiting → combine with **rate-limiting** on the same
  mutation (e.g., login, OTP verification) for a credential-stuffing or brute-force chain.
- Newly discovered types/fields from introspection → feed back into **api-discovery** to
  expand the overall endpoint/data map before closing this pass.
