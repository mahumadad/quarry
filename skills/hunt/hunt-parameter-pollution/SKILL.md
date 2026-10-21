---
name: hunt-parameter-pollution
description: >
  Hunt for HTTP Parameter Pollution (HPP): duplicate parameter names
  across query string/body/JSON that different layers of the stack
  (WAF, app server, backend logic) parse inconsistently, enabling filter
  bypass, logic bypass, or request routing confusion. Use when testing
  any endpoint with query/form parameters, especially behind a WAF or
  multi-tier architecture. Keywords: HPP, duplicate parameter, parameter
  pollution, array parsing, last-value-wins, first-value-wins.
  Do NOT use for JSON key confusion used for privilege escalation via
  extra object fields — use hunt-mass-assignment. Do NOT use for prototype
  pollution via nested keys like __proto__ — use hunt-prototype-pollution.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-235]
  mitre_attack: [T1190]
  tools: [burpsuite, curl, arjun, ffuf]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-broken-access-control, hunt-oauth, hunt-business-logic]
---

## Signals

- Any endpoint accepting multiple parameters of the same name is worth a baseline test — this applies broadly, not just to obviously unusual inputs.
- A WAF/reverse proxy in front of an app server of a different stack (e.g. ModSecurity + PHP, or an API gateway + a different backend language) — different languages parse duplicate params differently (PHP: last wins; ASP.NET: comma-joins values; Node/Express `qs`: array).
- Price/quantity/discount/role parameters that could plausibly be duplicated to confuse validation vs. processing logic.
- OAuth/redirect endpoints (dup `redirect_uri`, `scope`, `client_id` — see hunt-oauth for the OAuth-specific angle).

## Prerequisites

- Baseline single-value behavior documented for the target parameter before testing duplicates.
- Know (or fingerprint) the backend language/framework, since HPP behavior is framework-specific — test, don't assume.

## Methodology

1. **Baseline fingerprinting — how does the stack handle duplicates in general?** Pick a harmless reflected/echoed parameter and send it twice with different values:
   ```bash
   curl -s "https://target.com/search?q=first&q=second"
   ```
   Observe which value is used/reflected (first, last, concatenated, or treated as an array) — this tells you the parsing model for everything downstream.

2. **Query string vs body vs JSON divergence.** If a WAF inspects only the first occurrence of a param (common WAF behavior) but the app server uses the last, you can smuggle a malicious value past the WAF in the first slot and have the real value processed from the second:
   ```bash
   curl -s -i "https://target.com/api/transfer?amount=1&amount=99999" -b "session=$SESSION" -X POST
   curl -s -i -X POST "https://target.com/api/transfer" -H "Content-Type: application/x-www-form-urlencoded" \
     -b "session=$SESSION" -d "amount=1&amount=99999&to_account=1042"
   ```

3. **Filter/WAF bypass via duplicate params on known-signatured payloads.** If a WAF blocks a payload in the first/only occurrence, try splitting or duplicating so the dangerous value sits in the slot the WAF doesn't inspect:
   ```bash
   curl -s -i "https://target.com/search?q=safe&q=<script>alert(1)</script>"
   curl -s -i "https://target.com/search?q=<scr&q=ipt>alert(1)</script>"
   ```

4. **Authorization/role parameter duplication.** Test endpoints that accept a role/permission/account-id parameter alongside the session — duplicate it to see if validation checks one occurrence while business logic uses another:
   ```bash
   curl -s -i -X POST "https://target.com/api/account/switch" -b "session=$SESSION" \
     -d "account_id=1001&account_id=1002"
   ```

5. **Server-side request routing confusion.** On endpoints that proxy to another internal service based on a parameter, test whether duplicating the routing parameter causes the frontend validator and backend router to disagree:
   ```bash
   curl -s -i "https://target.com/api/webhook?target=https://allowed.com&target=http://169.254.169.254/latest/meta-data/"
   ```
   (This overlaps with SSRF scope — only pursue if SSRF is in scope and this is the delivery mechanism.)

6. **JSON array vs duplicate key test.** Some JSON parsers silently take the last duplicate key; test body-based endpoints too, not just query strings:
   ```bash
   curl -s -i -X POST "https://target.com/api/orders" -H "Content-Type: application/json" \
     -b "session=$SESSION" -d '{"price": 100, "price": 1}'
   ```

7. **Automate discovery across many endpoints** once the manual technique is validated:
   ```bash
   arjun -u "https://target.com/api/transfer" -m POST --headers "Cookie: session=$SESSION" -oJ arjun_out.json
   ```

## Tooling

- `curl` for precise duplicate-param crafting (both query string and body).
- Burp Suite Repeater/Intruder for quickly toggling which occurrence carries the "real" vs "decoy" value.
- `arjun` for parameter discovery that can surface candidate names worth duplicating.
- Framework-specific parsing reference (PHP `last wins`, ASP.NET `comma-joined`, Rails/Rack `array`, Express `qs` `array`) — verify empirically per target rather than trusting the reference alone.

## Root Causes

- Different components in the request path (WAF, API gateway, app server, backend service) parse duplicate parameters with different precedence rules, and security decisions are made by one component while business logic acts on another's interpretation.
- Input validation implemented against `request.GET['param']`-style single-value access while actual processing later iterates `request.GET.getlist('param')` or vice versa.
- No normalization/rejection of duplicate parameter names at the edge.

## Validation Gate (minimum proof)

- Two full request/response pairs: (a) single-value baseline, (b) duplicate-value test, showing the processed/business-logic outcome differs from what the (apparently validated) first/visible value would suggest — e.g. a transfer amount or role that doesn't match the value a naive read of the request would expect.
- For WAF bypass: proof the payload was blocked as a single param and passed through (with real effect) when duplicated — capture both WAF response (403/blocked) and the successful duplicated request's effect.
- Label as Demonstrated only once you've confirmed actual differing backend behavior, not just that duplicates are silently accepted without visible effect.

## Gotchas

- **Minimum proof:** the server accepting duplicate params without erroring is not itself a finding — you need a demonstrable security-relevant behavior divergence.
- **Common N/A:** strict schema validation (JSON Schema, typed request DTOs) that rejects duplicate keys or arrays where a scalar is expected — confirm via a 400 response and close as N/A.
- **Overclaim trap:** don't report "HPP vulnerability" generically — tie it to a specific exploitable outcome (filter bypass, authz confusion, logic bypass); parsing differences alone are informational.
- Test query string AND body AND JSON separately — a framework can handle each differently even within the same app.
- Some load balancers/CDNs de-duplicate or reject repeated params before the origin ever sees them — a clean negative at the edge doesn't prove the origin (if directly reachable, in scope) is safe.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **WAF/validation bypass** — Does duplicating the parameter bypass a validation or WAF rule that only inspects the first/last occurrence?
2. **Backend/frontend parsing mismatch** — Do the front-end validator and back-end parser pick different values for the same duplicated parameter, creating a logic bypass?
3. **Auth/IDOR chain** — Can parameter pollution override an ID or auth parameter set earlier in the request pipeline?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- WAF bypass via HPP → delivery mechanism for payloads under hunt-business-logic (price manipulation) or injection classes covered elsewhere.
- Duplicate `redirect_uri`/`scope` in an OAuth flow → chain fully into hunt-oauth.
- Role/account-id duplication bypassing an authz check → chain into hunt-broken-access-control for the resulting privilege impact.
- Duplicate routing parameter reaching an internal service → potential SSRF, flag for an SSRF-specific skill if present in this plugin.
