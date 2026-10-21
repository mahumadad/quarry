---
name: hunt-business-logic
description: >
  Hunt for business logic flaws: checkout/workflow step bypass, price/
  discount/coupon manipulation, negative or fractional quantity abuse,
  and race-condition-driven logic abuse (e.g. redeem a coupon twice).
  Use on any multi-step workflow with state transitions, pricing, or
  inventory (checkout, booking, loyalty points, referral programs).
  Keywords: business logic, workflow bypass, price manipulation, coupon
  abuse, negative quantity, race condition, step skipping, state
  machine.
  Do NOT use for pure technical injection/authz bugs with no business-rule
  component — those belong in their dedicated skills. This is specifically
  about abusing the *intended* logic/rules in unintended ways.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-840, CWE-841, CWE-362, CWE-20]
  mitre_attack: [T1499, T1190]
  tools: [burpsuite, curl, "Turbo Intruder"]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [hunt-parameter-pollution, hunt-mass-assignment, hunt-rate-limiting]
---

## Signals

- Multi-step checkout/booking/application flow (cart → shipping → payment → confirm).
- Client-side price/total calculation visible in JS, with the server trusting a submitted total.
- Coupon/promo code, referral bonus, or loyalty point redemption features.
- Quantity/amount fields with no visible bounds checking in the UI (can you type a negative number?).
- Any "state machine" status field (`pending → approved → shipped`) exposed or inferable via API.

## Prerequisites

- A complete legitimate walkthrough of the target workflow captured in Burp, every step logged, to know the exact sequence and parameters of a normal transaction.
- A disposable/test payment method or sandbox payment mode if the engagement scope allows (never use real financial instruments beyond what's explicitly authorized — see "Testing the user's own application" boundaries).

## Methodology

1. **Map the full state machine.** From the captured normal flow, list every step, every parameter, and every status transition. Identify which step the server considers "final"/authoritative (where payment is actually charged, where stock is actually decremented).

2. **Workflow step skipping.** Try calling a later-step endpoint directly without completing earlier steps:
   ```bash
   # skip straight to order confirmation without ever hitting the payment step
   curl -s -i -X POST https://target.com/api/checkout/confirm -b "session=$SESSION" \
     -d '{"cart_id":"abc123"}'
   ```
   Also try replaying/reusing a step's response from a *different* (abandoned or lower-value) cart/session against the final step.

3. **Repeat/replay a one-time step.** If a step is meant to happen once (apply coupon, redeem points, submit application), replay it:
   ```bash
   curl -s -i -X POST https://target.com/api/cart/apply-coupon -b "session=$SESSION" -d '{"code":"WELCOME10"}'
   curl -s -i -X POST https://target.com/api/cart/apply-coupon -b "session=$SESSION" -d '{"code":"WELCOME10"}'
   # does the discount stack / apply twice?
   ```

4. **Price/total tampering.** Intercept the request that carries price/total and modify it directly, checking if the server recalculates server-side or trusts the client value:
   ```bash
   curl -s -i -X POST https://target.com/api/checkout/confirm -b "session=$SESSION" \
     -d '{"cart_id":"abc123","total":0.01}'
   ```
   Also test per-line-item price override if the cart API exposes it:
   ```bash
   curl -s -i -X POST https://target.com/api/cart/add -b "session=$SESSION" \
     -d '{"product_id":55,"quantity":1,"unit_price":0.01}'
   ```

5. **Negative/fractional/overflow quantity.** Submit unusual numeric values the UI wouldn't normally allow:
   ```bash
   curl -s -i -X POST https://target.com/api/cart/add -b "session=$SESSION" -d '{"product_id":55,"quantity":-5}'
   curl -s -i -X POST https://target.com/api/cart/add -b "session=$SESSION" -d '{"product_id":55,"quantity":0.5}'
   curl -s -i -X POST https://target.com/api/cart/add -b "session=$SESSION" -d '{"product_id":55,"quantity":99999999999}'
   ```
   A negative quantity combined with a per-unit price can flip a total negative, potentially crediting the attacker's account/balance rather than charging it — check the resulting order total carefully.

6. **Coupon/promo brute-force and logic abuse.** Test whether coupon codes follow a predictable pattern, whether expired/single-use coupons are actually invalidated server-side, and whether stacking multiple codes is blocked:
   ```bash
   for code in WELCOME10 WELCOME20 SAVE10 SAVE20 NEWUSER FIRST50; do
     curl -s -o /dev/null -w "$code -> %{http_code}\n" -X POST https://target.com/api/cart/apply-coupon \
       -b "session=$SESSION" -d "{\"code\":\"$code\"}"
   done
   ```

7. **Race condition on single-use logic.** Fire the one-time action concurrently to see if a time-of-check/time-of-use gap allows it to succeed more than once (classic coupon/gift-card/limited-stock-item double-redemption):
   ```bash
   for i in $(seq 1 20); do
     curl -s -o /tmp/race_$i.json -X POST https://target.com/api/cart/apply-coupon \
       -b "session=$SESSION" -d '{"code":"ONETIME50"}' &
   done
   wait
   grep -l '"success":true' /tmp/race_*.json | wc -l   # should be 1, not >1
   ```
   For higher-fidelity race timing, use Burp Suite's **Turbo Intruder** with a single-packet attack to minimize network jitter between parallel requests.

8. **Referral/loyalty abuse.** Check if referring yourself (new account referring the original, or circular referral chains) grants bonuses not intended for self-referral.

9. **Inventory/stock logic.** If stock is decremented at "add to cart" rather than "payment confirmed", test holding items in cart indefinitely across many sessions to deny other users ("inventory denial of service" via logic, not technical exhaustion).

## Tooling

- Burp Suite Repeater for step-by-step manual manipulation.
- Burp **Turbo Intruder** for precise race-condition timing (single-packet attack technique).
- `curl` with backgrounded (`&`) parallel requests for simpler race tests when Turbo Intruder isn't available.
- A maintained list of common/guessable promo code patterns for the brute-force step.

## Root Causes

- Server trusts client-submitted price/total/quantity instead of recalculating from source-of-truth catalog data at the final step.
- One-time actions (coupon redemption, point transfer) implemented as read-then-write without a database-level unique constraint or atomic check-and-set, creating a race window.
- Workflow steps implemented as independent stateless endpoints with no server-side enforcement of step order (each step trusts the client reached it legitimately).
- No bounds validation on numeric business fields (quantity, amount) beyond what the UI widget happens to restrict.

## Validation Gate (minimum proof)

- Price/total tampering: request/response showing an order confirmed at a price obviously below the real catalog price, with a follow-up check (order detail / receipt) confirming the manipulated price was actually charged/recorded, not just accepted and silently corrected.
- Step-skip: proof a later step succeeded without the required prior step's data ever being submitted in that session.
- Race condition: numeric proof — N concurrent requests, M successes where M > 1 for an action meant to succeed once — include the raw count and timestamps.
- Coupon/negative-quantity abuse: the resulting order/balance showing the unintended financial outcome.
- Label clearly as Demonstrated only when the manipulated state is confirmed to persist (via an independent read), not just accepted in the mutating response.

## Gotchas

- **Minimum proof:** a 200 response to a tampered price is not enough — orders are frequently re-validated/corrected asynchronously (webhook from payment processor, nightly reconciliation) — confirm the *persisted* record, ideally via order history/receipt.
- **Common N/A:** server recalculates total server-side from `product_id`+`quantity` alone, ignoring any client-submitted price/total field entirely — close as N/A after confirming via a tampered-and-then-verified order.
- **Overclaim trap:** demonstrating a race condition theoretically "could" double-redeem without actually getting ≥2 successes in a real concurrent test is Unproven — run the test and report the actual count.
- Never use a real payment instrument or push an actual financial transaction beyond what's explicitly authorized by the engagement scope and the "Testing the user's own application" test-mode boundaries — use sandbox/test payment credentials only.
- Business logic findings often require deep context about the *intended* rule — confirm with the operator what the correct behavior should be before over- or under-claiming severity.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Financial impact** — Does the logic flaw let you underpay, double-claim, or extract value (discount stacking, negative quantities, currency rounding)?
2. **Workflow step skipping** — Can you skip a required step in a multi-step workflow (approval, payment, verification) and still reach the end state?
3. **State machine abuse** — Can you force the resource into an invalid state transition not reachable through the normal UI?
4. **Scale of abuse** — Can the flaw be automated/scripted for repeated abuse, or is it a one-off edge case?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- HTTP Parameter Pollution duplicating `quantity`/`price` params to confuse validation vs. processing layers → chain with hunt-parameter-pollution.
- Mass-assignable `price`/`discount` fields on a cart API → chain with hunt-mass-assignment.
- Lack of rate limiting enabling the coupon brute-force or race-condition fan-out at scale → chain with hunt-rate-limiting.
- Negative quantity flipping a charge into a credit → potential chain into account balance/wallet features if present.
