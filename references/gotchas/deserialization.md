# Gotchas: Insecure Deserialization

## Common False Positives
- A serialized-looking blob (base64, JSON with type hints, binary header) that is only an opaque, signed or encrypted token the server validates before parsing. Format recognition is not exploitability.
- Cookie or parameter that decodes to a recognizable serialization format but is protected by an HMAC or authenticated encryption; tampering is rejected before deserialization.
- JSON or XML data binding with a hardened library that does not instantiate arbitrary types (no polymorphic type handling, default typing disabled, safe-mode loaders).
- Libraries that implement class allowlisting (allow-list filters, look-ahead deserialization, restricted type resolvers). Gadget classes not on the list cannot be instantiated, so known gadget chains do not apply.
- Serialization used only for data at rest by trusted internal components, with no attacker-reachable input path.
- Error messages mentioning a deserialization library that arise from malformed input in a parser layer, not from arbitrary object instantiation.
- Out-of-band interaction triggered by an unrelated component (proxy, scanner, logging, email service) rather than the deserializer.
- A framework version "known to be vulnerable" where the vulnerable feature (e.g. default typing, remoting endpoint) is not enabled in this deployment.
- Scanner flags based on content-type or file extension (`.ser`, `application/x-java-serialized-object`) without a server that consumes it.

## Overclaim Traps
- "RCE via deserialization" claimed from a version banner or a detected library. Exploitability depends on reachable sink, configuration and available gadget classes on the classpath/runtime.
- Claiming a gadget chain works because it works in another application using the same library. Gadgets depend on the target's dependency set.
- Reporting tampering success (changed serialized field, role escalated) as RCE. That is an integrity or authorization issue; label it accordingly.
- Claiming impact from a DNS or HTTP callback alone: it demonstrates instantiation or network-capable behavior, not necessarily code execution or data access. State exactly what was demonstrated.
- Treating a denial-of-service via crafted object size as RCE, or running destructive payloads in production to "prove" it.
- Ignoring mitigations in place (egress filtering, sandboxing, container isolation, least-privileged service account) when rating impact.
- Counting each endpoint sharing the same deserialization helper as a separate Critical.

## Minimum Proof Required
- Evidence that attacker-controlled data reaches a deserializer: behavior changes in response to structurally valid, benign modifications of the serialized input (e.g. a field value reflected, a type error specific to the format).
- Evidence of absence of integrity protection: modified data is accepted rather than rejected on signature or MAC failure, with an unmodified control that behaves identically.
- Confirmation of the library and mode in use through observed behavior (error format, stack trace, headers) rather than guesswork.
- For object-instantiation claims: a harmless, operator-approved, non-destructive demonstration (for example an interaction on infrastructure you control with a unique identifier, with the source IP matching the target). Do not run commands, write files or alter data in production.
- For command execution claims: explicit operator approval at the exploitation gate, minimal read-only proof (such as a harmless identifier value), full request and response, and a record of cleanup. Prefer proving a lower-impact claim (instantiation) and stopping.
- Mitigating controls observed (allowlists, signing) documented with their effect on exploitability.
- Label the claim: Demonstrated (benign instantiation or execution proof under approval), Inferred (tamper accepted, sink reachable), Unproven (format spotted).

## When to Mark N/A
- No endpoint accepts serialized objects from clients; data exchange uses plain primitives with schema validation.
- All serialized client-held state is signed or encrypted with authenticated encryption and tamper tests fail closed.
- The deserialization library enforces a strict allowlist of types or disables polymorphic/default typing, confirmed by version, configuration or behavior.
- The deserialization path is reachable only by trusted internal systems outside the engagement scope.
- Testing would require destructive or out-of-scope payloads: record as "Not tested (RoE limits)".
