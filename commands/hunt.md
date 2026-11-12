---
name: quarry:hunt
description: Hunt by vulnerability class — all classes/assets or a filtered subset
argument-hint: "[class] [--asset <asset>]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:hunt [class] [--asset <asset>]

Runs the `*` skills against the scope. Without arguments, runs ALL
classes against ALL assets, breadth-first (plugin `CLAUDE.md` rule:
cover breadth before depth). With `[class]`, limits to that class
across all assets. With `--asset <asset>`, limits to that asset across
all classes (or the given class, if both are combined).

## Precondition

- Phase `MAPPED` or `HUNTING`. If the engagement is in `RECON` without
  having gone through `/quarry:map`, warn that hunting without maps loses
  trust/identity/capability context — allow if the operator insists
  (trivial target), but log the decision.
- Re-read existing `coverage.json` and `findings.json` before starting
  — do not rescan a cell already marked `tested_clean` or
  `finding_detected` unless the operator explicitly requests a re-test.

## Class → skill mapping

`engine/coverage.py` defines `ALL_VULN_CLASSES`. Each class maps to a
skill in `skills/hunt/`; several classes share a skill when they are
variants of the same technique:

| Skill (`skills/hunt/<x>`)   | Vuln classes covered                                |
|------------------------------|------------------------------------------------------|
| sqli                   | sqli                                                 |
| xss                    | xss-reflected, xss-dom, xss-stored                  |
| ssrf                   | ssrf                                                |
| idor                   | idor                                                |
| csrf                   | csrf                                                |
| rce                    | rce                                                  |
| ssti                   | ssti                                                 |
| xxe                    | xxe                                                   |
| lfi-rfi                | lfi, rfi                                             |
| auth-bypass            | auth-bypass                                          |
| race-condition         | race-condition                                       |
| cors                   | cors                                                  |
| open-redirect          | open-redirect                                        |
| info-disclosure        | info-disclosure                                      |
| deserialization        | deserialization                                       |
| graphql                | graphql                                              |
| websocket              | websocket                                            |
| jwt                    | jwt                                                   |
| oauth                  | oauth                                                 |
| api-abuse              | api-abuse                                            |
| file-upload            | file-upload                                          |
| cache-poisoning        | cache-poisoning                                      |
| http-smuggling         | http-smuggling                                        |
| subdomain-takeover     | subdomain-takeover                                    |
| crlf-injection         | crlf-injection                                        |
| clickjacking           | clickjacking                                          |
| host-header            | host-header-injection                                 |
| parameter-pollution    | parameter-pollution                                   |
| prototype-pollution    | prototype-pollution                                   |
| mass-assignment        | mass-assignment                                       |
| broken-access-control  | broken-access-control                                 |
| business-logic         | business-logic                                        |
| rate-limiting          | rate-limiting                                         |
| password-reset         | password-reset                                        |
| 2fa-bypass             | 2fa-bypass                                            |
| session-management     | session-management                                    |
| email-injection        | email-injection                                        |

If `[class]` is passed and does not match either a skill name or a class
from `ALL_VULN_CLASSES` (compare with `lower().replace('_','-')`
normalization), list the valid classes and ask to repeat the command.

## Endpoint understanding before testing

Before testing any endpoint, answer these four questions (from the mapping phase
output or by inspecting the endpoint directly). Scanners test what code does;
they don't know what it's supposed to do — that gap is where non-duplicate bugs live.

1. **What is this supposed to do?** — The business function, not the HTTP verb.
2. **Who is allowed to do it?** — Which roles, auth levels, or identity contexts.
3. **What parameters does it take, and what could each one be swapped for?** —
   Especially IDs, enums, and references to other objects.
4. **What happens if done out of order, twice, or as the wrong person?** —
   State-dependent bugs (race conditions, TOCTOU, replay) hide here.

If the mapping phase did not produce answers for a specific endpoint, gather them
before burning budget on scan tools. A single well-understood endpoint yields
more findings than ten endpoints poked blindly.

## Exact steps

1. Resolve the granular cell set: `asset × class × endpoint × method ×
   parameter × identity × technique`. Without arguments, all cells
   registered in `coverage.json` are covered; the `[class]` and `--asset`
   filters narrow that set without removing granularity.
2. Filter against `coverage.get_gaps()` unless explicit re-test. A cell
   with status `partial`, `inconclusive`, `blocked`, `tool_unavailable`,
   or `deferred` is still a gap; it does not count as conclusive coverage.
3. For each cell, read its skill and use `ToolRunner` or
   `ProtectedHTTPClient`. Save raw artifacts first with `ArtifactStore`;
   include their IDs in the result. If the skill is missing, register
   `blocked` with a content gap — do not improvise and mark conclusive
   coverage.
4. Execute the test. Possible outcomes:
   - **No finding, complete evidence** → `mark_tested(...,
     status="tested_clean", evidence_artifacts=[...], evidence_complete=True)`.
   - **Candidate finding** → create `Finding` at `DETECTED` and mark
     `finding_detected` only with complete evidence references.
   - **Timeout, incomplete response, or ambiguous result** → `inconclusive`.
   - **Missing tool** → `tool_unavailable`.
   - **Not supported by the technology** → `not_applicable` with evidence
     explaining why.
   - **Out of scope** → `out_of_scope`; **gate pending** → `blocked`;
     **postponed** → `deferred`. Never use `skipped` as a catch-all.
5. A finding at `DETECTED` is not definitive — do not report it as
   confirmed yet. Attempt to manually reproduce it once (not in a loop)
   to promote it to `CONFIRMED` via
   `FindingsStore.update_status(id, FindingStatus.CONFIRMED, reason=...)`
   if reproduction is clean; if it does not reproduce, leave it at
   `DETECTED` with a note, or kill it (`KILLED`) if it was clearly a
   scanner false positive.
6. Respect budget: before each new class, check
   `BudgetManager.record_call(phase="hunting", command=...)`. If
   `allowed=False`, stop and escalate to the operator (plugin `CLAUDE.md`
   rule: 80% budget without progress → escalate).

## Human gate

Any technique that mutates target state (writes, real data mutation,
sending real emails/SMS, race conditions against financial functions)
requires explicit operator confirmation BEFORE execution, even in
"breadth-first" mode without arguments. No exceptions for volume — if
the full hunt requires 10 confirmations, request them all, grouped when
possible to avoid unnecessary flow interruption.

## Edge cases

- **Class not applicable to the asset's technology** (e.g. `ssti` on
  an asset that serves only static JSON without a template engine): mark
  `skipped` with a concrete reason ("no template engine detected in
  tech-stack-fingerprint"), not "tested_clean" — these are distinct
  states.
- **Asset stops responding / aggressive rate-limit**: pause that row,
  continue with other assets, document the threshold, do not retry in a
  loop (max 3 attempts).
- **Same root cause across multiple cells** (e.g. missing output
  encoding affects 3 distinct endpoints under xss-reflected): register
  as separate findings for now — formal deduplication is the job of
  `/quarry:validate` (dedup step), not hunt.
- **Finding that clearly belongs to another class** (e.g. while testing
  for SSRF an IDOR is found): register it under the correct class
  immediately, do not force it into the cell being tested.

## Expected output

- Run summary: cells tested, clean, with finding, and skipped — with
  reasons.
- List of new findings (ID, class, asset, preliminary severity, status).
- Updated coverage ratio (`CoverageTracker.summary()`).
- Recommended next step: if ≥2 findings are `CONFIRMED` or `EXPLOITED`,
  `/quarry:chain`; otherwise, continue with pending cells or
  `/quarry:validate` on what exists so far.
