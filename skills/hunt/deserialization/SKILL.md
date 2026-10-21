---
name: hunt-deserialization
description: >
  Hunt for insecure deserialization: identify serialization formats in transit (Java
  ObjectInputStream, PHP serialize/unserialize, Python pickle, .NET BinaryFormatter/
  ViewState, Ruby Marshal), assess library/framework versions against known gadget-chain
  CVEs, and confirm whether untrusted input actually reaches a deserialization sink. Use
  whenever a request/response/cookie carries a binary blob, a base64 value with a
  serialization magic byte, or a framework known to deserialize client-controlled state
  (Java app servers, PHP apps with session/cache serialization, .NET ViewState, Python
  pickle-based caches/queues).
  Keywords: deserialization, ObjectInputStream, gadget chain, ysoserial, PHP unserialize,
  Python pickle, .NET BinaryFormatter, ViewState, Java RMI, Marshal.load, ACE via
  deserialization.
  Do NOT use for generic object-injection in templating engines (that's hunt-ssti) or for
  prototype pollution in JS (hunt-prototype-pollution) — this skill is specifically about
  native serialization formats reconstructing objects/state from untrusted bytes.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-502]
  mitre_attack: [T1190, T1059]
  tools: [curl, burpsuite, ysoserial, "Java Deserialization Scanner", phpggc]
depends_on: [active-recon, web-crawling, tech-stack-fingerprint]
feeds_into: [chain-analysis, rce]
chains_with: [rce, info-disclosure, auth-bypass]
---

## Signals

- Base64 or raw binary values in cookies, hidden form fields, or request bodies that decode
  to a recognizable serialization magic byte/header:
  - Java: `0xAC 0xED` (hex) at the start of the decoded bytes.
  - PHP `serialize()`: strings starting with a type-length prefix like `a:`, `O:`, `s:`, `i:`.
  - Python `pickle`: opcodes starting with `\x80` (protocol 2+) or printable opcodes for
    protocol 0 (`(dp0`, `c__main__`, etc.).
  - .NET `BinaryFormatter`/ViewState: base64 blobs, ViewState (`__VIEWSTATE`) with a
    `/wEP...` prefix when MAC validation is absent or disabled.
  - Ruby `Marshal`: binary blobs starting with a version byte pair like `\x04\x08`.
- Framework/library fingerprint from recon (via `tech-stack-fingerprint`) matches a known
  vulnerable serialization library version (e.g., old Apache Commons Collections, old
  Jackson with polymorphic typing enabled, old PHP frameworks with known unserialize gadget
  classes, .NET ViewState without `EnableViewStateMac`).
- Error messages on malformed input mentioning `ObjectInputStream`, `readObject`,
  `ClassNotFoundException`, `unserialize(): Error at offset`, `pickle.UnpicklingError`, or
  `.NET` deserialization exceptions — these confirm a deserialization sink exists even
  before any gadget chain is attempted.
- Caching/session layers (Redis, Memcached, session files) known to store serialized PHP/
  Java objects, reachable indirectly through another vuln (SSRF, LFI) that lets you write
  to the store.

## Prerequisites

- Confirmed reachable sink: a parameter, cookie, or header whose value is deserialized
  server-side. Passive confirmation (magic bytes + framework fingerprint) is enough to
  start; active confirmation (step 3 below) is required before claiming anything beyond
  "format identified."
- Knowledge of the exact library/version in use — gadget chain availability is entirely
  version-dependent. Do not attempt generic chains against an unidentified version.
- Explicit scope and gate confirmation before any object-instantiation test, per project
  rules — these tests can cause side effects (resource exhaustion, state corruption, in the
  worst case code execution) even when "just testing."

## Methodology

1. **Format identification (passive).** Decode every binary/base64-looking value observed
   in requests and responses and classify by magic bytes/structure:
   ```bash
   echo "$VALUE" | base64 -d | xxd | head -5
   # Java: starts with ac ed 00 05
   # .NET BinaryFormatter: starts with 00 01 00 00 ... or similar header pattern
   ```
   For PHP, inspect the raw (often un-encoded) cookie/param value directly for the
   `a:N:{...}` / `O:N:"ClassName":M:{...}` structure.

2. **Sink confirmation via malformed input (passive/low-risk).** Send a syntactically
   invalid but harmless payload of the same format and inspect the error:
   ```bash
   curl -s -i https://target/endpoint \
     -H "Cookie: session=TRUNCATED_BASE64_FRAGMENT"
   ```
   A deserialization-specific error (as listed under Signals) confirms the sink exists.
   A generic 400/401 with no framework-specific trace means you have not yet confirmed a
   reachable sink — stop here and mark as Unproven rather than assuming.

3. **Version-matched gadget-chain research (before any active test).** With the exact
   library/version from recon, check whether a public gadget chain exists for that version
   (`ysoserial` payload list for Java, `phpggc` gadget chain list for PHP, known-vulnerable
   `Jackson`/`Fastjson` polymorphic type configs, known .NET `ObjectDataProvider` chains).
   If no version-matched chain is known, this stays Unproven/Inferred — do not improvise a
   chain against an unconfirmed version.

4. **Side-effect probe (requires explicit gate).** With operator authorization, use a
   version-matched, *non-destructive* gadget (e.g., one that triggers a DNS lookup, a sleep,
   or writes an identifiable canary file to a scratch path) rather than a gadget chain aimed
   directly at code execution, to separate "deserialization triggers attacker-controlled
   object construction" from "and that construction has a dangerous side effect":
   ```bash
   # example shape only — exact invocation depends on the matched library/version
   ysoserial -p <MatchedPayload> -c "nslookup canary.yourdomain.com" > payload.ser
   curl -s -i https://target/endpoint --data-binary @payload.ser
   # confirm the DNS lookup arrived at your controlled resolver/listener
   ```

5. **For .NET ViewState specifically**, check whether `EnableViewStateMac` and
   `ViewStateEncryptionMode` are both effectively disabled before assuming forgeable
   ViewState is viable — most current frameworks default this on, and a tampered ViewState
   failing MAC validation (visible as a generic error, not a deserialization trace) is a
   different, weaker finding (integrity check working as intended) than a successful bypass.

6. **Confirm no secondary mitigation is masking a true negative**, e.g., `ObjectInputFilter`/
   look-ahead deserialization allow-listing on the JVM, PHP `__wakeup`/`__destruct`
   hardening, or a WAF rule specific to known gadget chain signatures — a blocked request
   with a WAF fingerprint is a different finding than "deserialization sink doesn't exist."

## Tooling

- `ysoserial` — generates Java gadget-chain payloads for known library/version
  combinations; only useful once the exact vulnerable dependency is confirmed.
- `phpggc` — equivalent gadget-chain generator for PHP object-injection chains.
- Burp Suite's **Java Deserialization Scanner** extension — passive detection of
  serialized-object patterns in traffic plus semi-automated gadget probing.
- `xxd`/`base64` — manual byte-level inspection, the first and cheapest step every time.

## Root Causes

- Server-side code calling a native deserialization API (`ObjectInputStream.readObject`,
  PHP `unserialize()`, Python `pickle.loads()`, .NET `BinaryFormatter.Deserialize`, Ruby
  `Marshal.load`) directly on attacker-controlled bytes, with no type allow-list.
- Vulnerable gadget classes present on the classpath/dependency tree (common transitively
  through unrelated libraries) that can be chained into dangerous behavior once any
  deserialization entry point exists.
- Integrity controls (HMAC/signing) on serialized state either absent or not actually
  verified before deserialization occurs.

## Validation Gate (minimum proof)

- Minimum: confirmed **object instantiation or an observable side effect** attributable to
  the deserialization process — a canary DNS/HTTP callback, a confirmed sleep/delay, a file
  written to a path you control, or an identifiable exception stack trace showing gadget
  class construction. Format identification alone (step 1) is not sufficient to report
  beyond "serialization format identified, sink unconfirmed."
- Full exploitation (code execution) is a separate, higher gate requiring explicit operator
  authorization per project rules — do not escalate from a canary callback straight to an
  RCE claim without that separate step and sign-off.
- Every claim above "format identified" needs the exact payload sent and the exact
  observable response/callback captured, labeled Demonstrated/Inferred/Unproven.

## Gotchas

- **Overclaim trap:** detecting a known-vulnerable library version on the classpath is
  **Inferred** at most, never Demonstrated, until an actual payload produces an observable
  side effect — per project anti-fabrication rules, "Commons Collections 3.1 on classpath"
  is not itself a finding.
- **Overclaim trap:** a 500 error after sending a malformed serialized blob is not proof of
  deserialization — many frameworks throw a generic exception for any malformed body
  regardless of content type. Confirm the error trace is specific to a deserialization call
  path, not just "any parse error."
- **Common N/A:** `ObjectInputFilter`/allow-list deserialization, signed/HMAC-validated
  serialized state actually verified before use, or a framework that has fully migrated off
  native serialization (e.g., JSON-only session storage) — verify the control is real (not
  just present in config) before closing.
- Gadget chains are brittle across minor versions — a chain working on 3.1 failing on 3.2.1
  is expected and not evidence the app is safe; it only means that specific chain doesn't
  apply.
- Never aim a gadget chain directly at destructive code execution as a first test — use a
  non-destructive canary (DNS/HTTP callback, sleep) to confirm the primitive before any
  escalation, and only with explicit operator sign-off per the human-gate rules.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Gadget chain to RCE** — Does a known gadget chain for the library/framework in use achieve full RCE, not just object instantiation or a crash?
2. **DoS via recursive/oversized payload** — Can a crafted payload (deeply nested, billion-laughs-style) cause resource exhaustion?
3. **Property/field injection** — Does deserializing attacker-controlled data let you set internal fields that bypass app-level validation (role, balance, ownership)?
4. **Blind deserialization confirmation** — If no direct output is visible, can you confirm execution via an out-of-band channel (DNS/HTTP callback)?
5. **Cross-service reach** — Is the vulnerable deserialization reachable from an internal queue/message bus, widening the attack surface beyond the HTTP API?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Confirmed side effect with a code-execution-capable gadget → feeds **rce** for the full
  exploitation assessment (separate gate).
- Deserialization sink reachable only after another vuln grants write access to a cache/
  session store (SSRF to internal Redis, LFI to a session file) → chain with those skills in
  **chain-analysis**.
- Version/library fingerprint feeding this hunt comes from **tech-stack-fingerprint**; keep
  that recon current before re-testing after a deploy.
