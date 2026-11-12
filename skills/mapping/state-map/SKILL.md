---
name: state-map
description: >
  Map where and how the target manages state: session storage, caches
  (Redis, Memcached, CDN edge cache), databases (relational, NoSQL, search
  indices), message queues/event buses, file storage (local, object storage,
  temp dirs), and any other persisted or transient state. Identifies which
  state is shared across trust boundaries, which is attacker-reachable, and
  which is vulnerable to poisoning, races, or stale-data exploitation.
  Use after asset-map/trust-map to catalogue stateful components before
  testing race conditions, cache poisoning, deserialization of stored state,
  or session-related attacks.
  Do NOT use for auth token semantics — use identity-map.
  Do NOT use for what a component can actively *do* (exec, network) — use
  capability-map.
metadata:
  type: mapping
  phase: mapped
  tools: [redis-cli, curl, nmap, burp, race_the_web, turbo_intruder, nosqlmap]
depends_on: [asset-map, trust-map]
feeds_into: [chain-analysis, chain-idor-to-mass-data, capability-map]
chains_with: [chain-idor-to-mass-data]
---

## Signals

- asset-map surfaced a Redis/Memcached/DB port exposed beyond where it should be.
- Testing for race conditions (double-spend, limit bypass) requires knowing where the
  authoritative state lives and whether the check-then-act sequence is atomic there.
- Session or cache behavior looks inconsistent across requests (stale reads, cross-user
  bleed) and you need to map the actual storage/propagation path to explain it.
- Preparing to test cache poisoning, deserialization, or stored-state tampering.

## Prerequisites

- Completed asset-map (for exposed stateful service ports) and trust-map (for which
  boundaries each stateful component sits behind).
- A foothold sufficient to send repeated/concurrent requests against target endpoints for
  timing analysis, within RoE-permitted load limits.

## Methodology

1. **Inventory every stateful component.** From asset-map, list every DB (SQL/NoSQL/search),
   cache (Redis/Memcached/Varnish/CDN edge), queue/broker (Kafka/RabbitMQ/SQS), and storage
   backend (local disk, S3/GCS/Azure Blob, temp directories). For each, note version,
   exposure (internal-only per trust-map, or reachable from a lower-trust zone), and whether
   it requires auth to connect directly.

2. **Map session state specifically.** Where does session state live — server-side (DB/
   cache-backed, invalidatable) or entirely client-side (signed/encrypted cookie, JWT)? If
   server-side, what's the key (session ID entropy, predictability) and what invalidates it
   (logout, password change, explicit revocation, or nothing)? If client-side, what prevents
   replay of an old token after it should be invalid?

3. **Map cache layers and their keys.** For each cache (app-level, CDN, reverse-proxy), note
   what's cached, the cache key composition (does it include auth state, cookies, headers?),
   and the TTL/invalidation trigger. A cache keyed without regard to user/auth context is a
   direct cache-poisoning/cross-user-leak candidate — flag it immediately, it's a near-
   guaranteed finding, not just a mapping note.

4. **Map database consistency boundaries.** Identify where multi-step business logic (check
   balance → debit → credit, check stock → reserve → confirm) spans multiple queries without
   a transaction or lock. This is the direct input to race-condition testing — record the
   exact endpoint and the exact check-then-act gap.

5. **Map queues and async processing.** For each queue/event consumer, note what triggers a
   message, what validates the message *consumer-side* (vs just producer-side), and whether a
   message can be crafted/replayed/duplicated by an attacker who controls the producer
   boundary (e.g. a webhook endpoint that enqueues a job based on unauthenticated input).

6. **Map file storage paths.** For uploaded files: where do they land (local path, object
   storage key), is the path influenced by user input (traversal candidate), is content-type
   or extension enforced at write time vs just at serve time, and is the storage bucket/path
   publicly readable by default or by misconfiguration.

7. **Map temp/ephemeral state.** Build artifacts, export jobs, PDF/image generation
   intermediates, debug dumps — anything written to a temp location and later served or
   cleaned up. Race conditions and predictable temp paths live here.

## Validation gate

- Every stateful component has a recorded exposure level (who can reach it directly) cross-
  checked against trust-map, not assumed from its name.
- Every check-then-act sequence flagged as a race candidate has the actual endpoint sequence
  and the specific state it reads/writes, not a generic "might race" note.
- Cache-key composition claims are based on observed `Vary`/cache-control behavior and
  repeated requests with varied auth context, not documentation alone.

## Gotchas

- Redis/Memcached with no auth bound to localhost is fine; the same service bound to
  `0.0.0.0` reachable from an adjacent container/VPC is a finding — the difference is
  entirely about trust-map's verified reachability, not the service's default config.
- CDN edge caches frequently cache authenticated responses when `Vary: Cookie` or
  `Cache-Control: private` is missing — this is one of the highest-yield, easiest-to-miss
  findings in this category; always test it directly with two different authenticated
  sessions.
- A race condition only matters if the *business* state it corrupts is exploitable (double
  redemption of a coupon, double withdrawal) — map the business consequence, not just the
  technical gap, so capability-map and chain-analysis can use it.
- Object storage buckets often have per-object ACLs overriding bucket-level settings — a
  "private bucket" claim doesn't rule out individually public objects; sample-check, don't
  assume.
- Load testing for race conditions against production can cause real financial/business
  impact (actual double-spends) — confirm with the client whether race testing is permitted
  against prod or must be isolated to staging with seeded test data.
