---
name: race-condition
description: >
  Hunt for race conditions: TOCTOU (time-of-check-to-time-of-use) gaps, limit/quota bypass
  via concurrent requests, and double-spend/double-redeem scenarios. Use when a workflow
  checks a condition then acts on it (balance check then debit, coupon validity then
  redeem, one-time-use token then consume), especially under concurrency.
  Keywords: race condition, toctou, double spend, limit bypass, concurrent requests, single
  packet attack, request smuggling for timing, coupon abuse, inventory oversell, rate limit
  bypass via concurrency.
  Do NOT use for pure rate-limiting absence with no business-logic impact — that's a
  lower-severity info-disclosure/DoS-adjacent note, not a race condition finding by itself.
  Do NOT use for session-level CSRF/auth timing — use the respective dedicated skill.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-362, CWE-367]
  mitre_attack: [T1499]
  tools: [turbo-intruder, curl, race-the-web, python-asyncio]
depends_on: [active-recon, web-crawling, auth-mapping]
feeds_into: [chain-analysis, business-logic-impact]
chains_with: [idor, auth-bypass]
---

## Signals

- Any "check-then-act" business logic: balance/credit check before debit, coupon/voucher
  validity check before redemption, inventory count check before order placement, one-time
  password/token "has this been used?" check before marking used.
- Multi-step workflows split across more than one HTTP request where state persists between
  them (e.g., "apply coupon" then "checkout" as separate calls).
- Features with an explicit usage limit: "redeem this code once," "withdraw up to your
  balance," "invite N users max," "submit this form once."
- Endpoints doing a read-modify-write without an apparent transaction/lock (hard to confirm
  from the outside, but slow response times or inconsistent behavior under light concurrent
  load are a hint).

## Prerequisites

- A test account with a known, controlled balance/quota/coupon to abuse (e.g., one valid
  single-use coupon code, one account with a small test balance).
- A way to fire many requests with minimal client-side jitter — tooling matters a lot here;
  naive sequential `curl` in a bash loop usually won't expose the race window.
- Clear understanding this is destructive/state-changing by nature — confirm the specific
  limit/balance being tested is a test fixture, not shared/production data, before firing.

## Methodology

1. **Identify the exact check-then-act window.** Trace the request/response of the normal
   single-use flow once to understand the state transition (e.g., coupon status
   `unused → used`, balance `100 → 100-charge`).

2. **Single-packet / high-concurrency burst with Turbo Intruder** (most reliable technique —
   minimizes network jitter by queuing requests to fire near-simultaneously):
   ```python
   # turbo-intruder script: race.py
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                               concurrentConnections=20,
                               requestsPerConnection=1,
                               pipeline=False)
       for i in range(20):
           engine.queue(target.req, gate='race1')
       engine.openGate('race1')
       engine.complete(timeout=10)

   def handleResponse(req, interesting):
       table.add(req)
   ```
   Load `race.py` in Burp's Turbo Intruder extension against the captured redeem/debit request,
   fire the gated batch, and inspect how many of the N concurrent requests returned a "success"
   state rather than the expected single-success-rest-rejected pattern.

3. **Plain async/concurrent HTTP client** when Burp/Turbo Intruder isn't available:
   ```python
   import asyncio, httpx

   async def fire():
       async with httpx.AsyncClient() as client:
           tasks = [client.post("https://target/api/coupon/redeem",
                                 json={"code": "TESTCODE1"},
                                 cookies={"session": "VALIDSESSION"})
                    for _ in range(20)]
           results = await asyncio.gather(*tasks)
           for r in results:
               print(r.status_code, r.text[:100])

   asyncio.run(fire())
   ```

4. **Limit/quota bypass pattern** — fire N concurrent requests at a resource with a known hard
   cap (e.g., "withdraw up to $100 balance") each requesting the full amount, then check if the
   final balance went negative or multiple withdrawals succeeded:
   ```bash
   for i in $(seq 1 10); do
     curl -s -X POST https://target/api/withdraw -H "Cookie: session=$SESSION" \
       -d "amount=100" & 
   done
   wait
   curl -s https://target/api/balance -H "Cookie: session=$SESSION"
   ```
   A final balance below zero (or more than one withdrawal having succeeded) after a single
   $100 balance = confirmed race condition.

5. **Coupon/voucher double-redeem** — same pattern against a single-use code:
   ```python
   # using the asyncio snippet above against a known single-use coupon, confirm via
   # subsequent order totals: did more than one order receive the discount?
   ```

6. **Multi-endpoint race (different endpoints, same underlying resource)** — sometimes the race
   isn't on the *same* endpoint hit repeatedly, but on two different endpoints that both touch
   the same state (e.g., "apply discount" and "finalize order" both mutate the cart total) —
   fire both concurrently rather than N copies of one request.

7. **Single-packet attack variant** for HTTP/2-capable targets (reduces jitter further than
   HTTP/1.1 pipelining by sending all request frames in one TCP packet) — Turbo Intruder's
   `engine=Engine.THREADED2` or HTTP/2-specific single-packet tooling; use when the 20-connection
   burst in step 2 shows partial-but-inconsistent results, suggesting network jitter is masking
   a real, narrower race window.

## Tooling

- **Turbo Intruder** (Burp extension) — the standard tool for this class; gate-based queuing
  minimizes jitter far better than manual scripting.
- Python `asyncio`/`httpx` or `grequests` — scriptable alternative when Burp isn't in the
  toolchain.
- `race-the-web` — purpose-built CLI for this exact pattern (many parallel identical requests,
  compare outcomes).

## Root Causes

- Business logic reads state (balance, coupon status, inventory count), performs validation in
  application code, then writes the updated state back — with no database-level locking
  (`SELECT ... FOR UPDATE`), atomic increment/decrement, or unique constraint enforcing
  single-use semantics.
- Idempotency keys not implemented/enforced on payment or redemption endpoints.
- Application-level mutex/lock scoped incorrectly (per-request instead of per-resource, or not
  distributed across multiple app server instances behind a load balancer).

## Validation Gate (minimum proof)

- A measurable, incorrect final state after the concurrent burst: balance below the floor it
  should have hit, a single-use coupon applied more than once, an inventory count gone negative,
  or more invites/signups than the stated limit allowed.
- Document request count fired, how many "succeeded" per the app's own success signal, and the
  resulting actual state (balance/count) — this is the proof, more than any single response body.
- Reproduce at least twice to rule out a one-off fluke from unrelated test-environment flakiness.

## Gotchas

- **Minimum proof, not fund drainage.** Demonstrate the race with the smallest possible
  concurrent burst and the smallest test balance/coupon value that proves the bug; don't scale
  up to maximize extracted value.
- **Common N/A:** the endpoint is already protected by a database unique constraint or
  `SELECT FOR UPDATE` and the burst consistently yields exactly one success — that's the control
  working; a single anomalous result out of many repeated trials is more likely test noise than
  a real finding — rerun before concluding.
- **Common N/A:** client-side rate limiting/disabled-button UX only — doesn't matter for races,
  since the attacker bypasses the UI entirely; don't accept "the button disables after click" as
  a mitigating control.
- **Overclaim trap:** a race "window" observed only under artificial high concurrency (100+
  simultaneous requests) that never occurs in realistic usage patterns is still a real
  vulnerability (an attacker controls their own concurrency), but note the burst size required —
  it affects exploitability assessment, not whether it's a finding.
- Rerunning the exact same burst can sometimes show 1/20 succeeding falsely just from test
  environment scheduling variance — always correlate the "extra" success with an actual
  real-world-meaningful state change (money, inventory), not just an HTTP 200 among several 409s.
- CDN/WAF connection reuse or HTTP/1.1 keep-alive limits can serialize your "concurrent" requests
  without you noticing — verify with response timestamps that requests genuinely overlapped
  server-side, not just that you fired them close together client-side.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Success rate** — What is the success rate over 10 repeated attempts? A one-off win isn't a reliable finding.
2. **Financial double-spend** — Can you chain the race into a financial operation (balance deduction, wallet transfer) for a double-spend?
3. **Invite/coupon abuse** — Can you chain the race into invite codes, coupons, or promo redemption for multi-use of a single-use resource?
4. **Single-packet technique** — Does a single-packet/last-byte-sync technique improve the race's reliability over naive concurrent requests?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Race condition in coupon/discount logic → direct financial-impact finding, report with
  concrete monetary exposure if quantifiable from the test (e.g., "$X discount applied Nx via
  a single-use code").
- Race condition on account-linking/invite flows → **idor**-adjacent privilege escalation if the
  race lets one account claim a resource meant for another.
- Combined with **auth-bypass** multi-step MFA flows: racing the "verify" step against
  "issue session" step can sometimes let an attacker slip past a step that assumes sequential
  completion.
