---
name: chain-web-to-rce
description: >
  Analyze and validate web-vulnerability chains that escalate to remote code
  execution: file upload + path traversal, SSTI + sandbox escape,
  insecure deserialization, and SSRF reaching an internal service with its
  own code-exec surface. Use when chain-analysis flags a candidate whose
  endpoint is an RCE-capable capability (per capability-map) and whose
  precondition is a web-layer finding (upload, traversal, template
  injection, deserialization, SSRF).
  Do NOT use for chains ending in data exposure or account takeover without
  code execution — use chain-info-to-exploit or chain-auth-to-takeover.
metadata:
  type: chain
  phase: chaining
  tools: [burp, ysoserial, tplmap, curl, msfconsole, ffuf]
depends_on: [chain-analysis, capability-map]
feeds_into: [finding-validation, report-writing]
chains_with: [chain-ssrf-to-cloud, chain-info-to-exploit]
---

## Signals

- capability-map flagged a component as RCE-adjacent (template engine, deserializer, file
  converter shelling out, SSRF-capable service with reachable internal exec surface) and
  chain-analysis scored a pairing against it ≥1.
- A file-upload feature exists alongside a path-traversal or path-control bug anywhere the
  uploaded file is later read/executed/included.
- A template-rendering feature accepts user input into the template body/expression context,
  not just template variables.
- An endpoint deserializes a user-controlled payload (Java, .NET, PHP, Python pickle,
  Ruby Marshal) without integrity checking.

## Prerequisites

- Underlying web finding (upload, traversal, SSTI, deserialization point, or SSRF) already
  confirmed per finding-validation, or at minimum reachability-confirmed (Gate 2) with
  trigger testing pending.
- Explicit operator go-ahead before any payload that writes/executes on the target, per
  project CLAUDE.md human gates — this applies even when every prior step was pre-approved.

## Methodology

1. **File upload → path traversal → execution.**
   - Confirm upload accepts a file type that the serving/execution context would run (script
     language matching the backend, or a type an included library executes, e.g. an
     ImageMagick/PDF converter payload).
   - Confirm independently whether the storage path or the serving path is influenced by
     user input (traversal in filename, in a multipart field, or in a post-processing step).
   - Chain: upload a benign-marker payload first (e.g. a file that only proves write location
     and read-back, no execution) to confirm the traversal lands where expected, before
     attempting anything that executes.
   - Only after Gate 3 (Trigger) is satisfied non-destructively, and with explicit operator
     sign-off, attempt a minimal-impact execution PoC (e.g. a command that prints a marker
     string to a response or log you control — never a destructive or persistence action).

2. **SSTI → sandbox escape.**
   - Confirm template-context injection with a safe arithmetic/identity probe (`{{7*7}}` or
     engine-equivalent) before anything else — this proves injection without proving RCE.
   - Identify the exact template engine and version (error messages, response fingerprint).
   - Research whether that engine/version has a known sandbox-escape gadget chain; if it
     does, treat the specific CVE/gadget as the finding's basis, not a generic "SSTI implies
     RCE" claim — per project anti-fabrication rule, a CVE match alone isn't proof; you still
     need the real trigger.

3. **Insecure deserialization.**
   - Identify the serialization format from error messages, content-type, or source if
     available.
   - Confirm the endpoint actually deserializes attacker-controlled bytes (not just accepts
     them) — a non-crashing malformed payload that produces a type-confusion error is strong
     evidence.
   - Where a known gadget chain exists for the library/version in use (e.g. via `ysoserial`
     for Java), use the least-impactful gadget available for PoC (e.g. DNS/HTTP callback to
     an attacker-controlled listener) before anything resembling a shell.

4. **SSRF → internal exec surface.**
   - Use trust-map to identify what the SSRF-capable component can reach internally.
   - Confirm (via capability-map) whether anything reachable has its own exec-capable
     surface (an internal admin panel with command exec, an exposed Docker API, an internal
     CI/build trigger).
   - This is a two-hop chain: SSRF confirms reachability, the internal service's own flaw
     confirms execution — both legs need independent evidence.

## Validation gate

- A chain is only reported as "RCE" if a real code-execution trigger was demonstrated
  (output/callback observed), per project anti-fabrication rule — a reachable sink with no
  observed execution is reported as "Inferred," not "Demonstrated."
- The specific commands/payloads used are recorded verbatim in the evidence trail (minus any
  destructive component), timestamped, for report-writing.
- No destructive, persistent, or data-modifying payload is used without the explicit
  operator confirmation required by project CLAUDE.md human gates.

## Gotchas

- "Version X of library Y has a known RCE CVE" is not itself a finding — confirm the
  specific instance is reachable, unpatched, and actually triggerable in this target's
  configuration before claiming anything beyond "Unproven."
- Minimal-impact PoC commands (`id`, `whoami`, `sleep N` for blind confirmation, a callback
  to an attacker listener) are strongly preferred over anything that writes/deletes — choose
  the least invasive proof that still unambiguously demonstrates execution.
- A sandboxed template engine or restricted deserializer may block the obvious payload but
  still be exploitable via a less common gadget — don't conclude "not exploitable" from one
  blocked payload; also don't spend unbounded budget chasing it — if several good-faith
  attempts fail, log it as a dead end (per cobertura rule) and move on.
- File upload chains frequently depend on a race between upload and a cleanup/AV scan job —
  note timing sensitivity in the PoC steps so it's reproducible, not a one-off fluke.
- Blind RCE (no direct output) needs an out-of-band channel (DNS/HTTP callback) you control
  and can show logs for — don't claim execution from inference (e.g. "response time
  increased") alone.
