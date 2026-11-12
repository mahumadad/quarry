---
name: fuzzing
description: >
  Systematic fuzzing of APIs, parameters, and parsers beyond wordlist content discovery.
  Use when hunting input-validation bugs at scale: schema-driven API fuzzing
  (schemathesis/RESTler from an OpenAPI/GraphQL spec), stateful REST fuzzing,
  parameter value fuzzing with mutation (radamsa), file-format/parser fuzzing for
  upload endpoints, and coverage-guided fuzzing when source is available
  (AFL++/libFuzzer via SAST engagements). Keywords: fuzz, schemathesis, RESTler,
  radamsa, mutation, schema fuzzing, property-based, AFL, libFuzzer, corpus, crash
  triage.
  Do NOT use for directory/content brute-forcing (that is active-recon's ffuf job) or
  for targeted single-class payloads (use the specific hunt skill).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-20, CWE-1284]
  mitre_attack: [T1190]
  tools: [schemathesis, restler, radamsa, ffuf, afl-fuzz]
depends_on: [api-discovery, web-crawling, api-discovery]
feeds_into: [finding-validation, chain-analysis]
chains_with: [rce, deserialization, sqli, ssrf, dos]
---

## Signals

- API exposes an OpenAPI/Swagger spec (or one can be reconstructed from
  api-discovery output) → schema fuzzing gives near-free breadth.
- Endpoints accept structured bodies (JSON/XML/Protobuf) with nested types —
  hand-testing misses type-confusion, boundary, and missing-field crashes.
- File upload parsers (images, PDF, DOCX, SVG, archive formats) → classic
  fuzz target; crashes here are often memory-safety or parser-RCE leads.
- Source code available (SAST engagement) → coverage-guided fuzzing of the
  exact parser/handler is far deeper than black-box probing.

## Methodology

1. **Schema-driven API fuzzing (first choice when a spec exists):**
   ```bash
   schemathesis run --base-url https://target/api openapi.json \
     --checks all --hypothesis-deadline 5000
   ```
   Schemathesis generates valid + invalid inputs per schema, and checks
   server crashes (5xx), spec violations, and (with extensions) auth issues.
   RESTler (compile from spec → fuzz with dependency-aware sequences) for
   stateful APIs where endpoint B needs output of endpoint A.

2. **Mutation fuzzing of captured valid requests** when no spec exists:
   ```bash
   radamsa valid-request.json > mutated.json    # deterministic-seed batches
   ffuf -request req.txt -request-proto https -w mutated-corpus/ -mc all -fc 404
   ```
   Keep the valid baseline: a mutation that changes the response shape
   (500 vs 400, timing spike, partial content) is a triage lead.

3. **Parser/upload fuzzing:** mutate valid sample files per format (radamsa
   works fine for structured formats; format-specific tools for images),
   upload each, watch for: 500s, processing timeouts, changed error messages,
   and out-of-band callbacks (embed your OAST URL in formats that fetch
   external resources — SVG, DOCX, PDF).

4. **Coverage-guided (source available):** hand the SAST pipeline a fuzz
   harness task — AFL++/libFuzzer on the request parser, template renderer,
   or deserializer. Feed crashes back as hunt leads with the exact input.

5. **Crash triage — the anti-noise discipline.** Every crash/anomaly gets:
   minimize the input (smallest reproducer), reproduce 3x, identify the code
   path (error message / stack / logs if visible), then hand to the relevant
   class skill (a crash in query building → sqli; in template render → ssti).
   A bare 500 is a lead, NEVER a finding (evidence standards, SQLi N/A rule).

## Tooling

- `schemathesis` — property-based API fuzzing from OpenAPI/GraphQL schemas.
- `RESTler` — stateful REST fuzzing, infers producer-consumer dependencies.
- `radamsa` — general-purpose mutator for request bodies and files.
- `ffuf` — transport for replaying mutated corpora against endpoints.
- `AFL++` / `libFuzzer` — coverage-guided, source-available targets.
- OAST listener (engine/oast.py) — blind crash→callback escalation for
  server-side fetchers triggered by malformed documents.

## Validation Gate (minimum proof)

- Crash class identified with a minimized, reproducible input (3 consecutive
  reproductions) AND a plausible security impact path documented — otherwise
  record as "stability issue (unassessed security impact)", severity info.
- 5xx alone ≠ vulnerability. Escalate via the class skill until the class
  validation gate is met (e.g., SQL error content for SQLi, evaluated
  expression for SSTI, OAST callback for blind vectors).

## Gotchas

- **Rate limits and WAFs:** fuzzing is loud. Check rate-limiting first;
  throttle, and expect WAF blocks to create coverage holes — log them as gaps.
- **State destruction:** fuzzing state-changing endpoints (POST/PUT/DELETE)
  can pollute or damage data. Fuzz against staging where possible; in prod,
  restrict to read endpoints or get an explicit operator gate.
- **Hypothesis/schemathesis defaults shrink slowly** — always save the
  failing example it reports before moving on.
- **Don't fuzz auth endpoints aggressively** without an operator gate —
  lockouts can deny service to real users (scope violation risk).
- Fuzzing coverage is a **coverage report item**: record which endpoints were
  fuzzed, with how many cases, in the engagement's coverage gaps section.

## Chain Anchors

1. Reproducible crash in parser → memory corruption potential? If native code,
   flag for deeper exploitability analysis (may exceed engagement scope — gate).
2. Type-confusion accepted by API → test downstream: does the confused type
   reach a sink (query, template, command)? Hand to that class skill.
3. Malformed document triggers server-side fetch → blind SSRF via document
   parsers (combine with oob-interactions).
