# Gotchas: Race Conditions

## Common False Positives
- Idempotent operations that appear to run twice: duplicate successful responses (200/201) for an action whose backend deduplicates by idempotency key, unique constraint or natural key. Final state is unchanged, so there is no impact.
- Multiple "success" responses while the database holds one record. Responses can all be optimistic, queued or cached; verify state, not responses.
- Read-only endpoints or operations that merely return the same data concurrently.
- Database-level atomicity: transactions, row locks (`SELECT ... FOR UPDATE`), unique indexes, atomic increments or compare-and-swap that prevent the double-spend even though the application-layer code looks naive.
- Asynchronous processing with a later reconciliation job that corrects counts. The transient inconsistency may not be exploitable if reconciliation reverses the effect before value is extracted.
- Rate-limit counters appearing to exceed the limit due to distributed counter lag, with the excess requests ultimately rejected or reversed.
- Timing differences caused by network jitter, connection warm-up or HTTP/2 multiplexing rather than server-side concurrency windows.
- Inconsistency observed only in your own account's display (UI caching, eventual consistency) without durable backend change.
- Gift-card, coupon or invitation flows where the second redemption is queued, then failed, with the first being the only effective one.

## Overclaim Traps
- Reporting "double spend" or "limit overrun" without showing durable, extracted value (balance increased, two items shipped, two redemptions persisted, limit actually exceeded in stored state).
- Claiming financial impact from test-mode or sandbox payments. State clearly if the effect exists only in a test environment.
- Extrapolating one successful race to unlimited abuse. Measure the real success rate and the cap, and state the maximum demonstrated.
- Rating Critical when the exploitable window yields trivial value (a duplicate like, comment or notification).
- Treating a failed lock or missing mutex observed in code or error text as exploitable without a working reproduction.
- Calling application-level duplicates (two rows) a race when they are caused by client retries or double-click without server-side concurrency.
- Combining unrelated issues (rate limit weakness + race) without proving the chain.

## Minimum Proof Required
- Clear definition of the invariant that should hold (one redemption per coupon, balance never negative, one account per email) and the persisted state showing it was violated.
- Before/after state read from an independent source (separate API call or database-visible effect after the system settled), not only from the racing responses.
- Reproducibility: the result achieved multiple times with a stated success rate and the number of concurrent requests used. A one-off is Inferred.
- Control: sequential execution of the same requests respects the invariant, proving the violation comes from concurrency.
- Test-only data and accounts; amounts minimal; keep the number of concurrent requests as low as needed to demonstrate. Do not run high-volume concurrency against production without operator approval.
- Reversal or cleanup performed or documented so the target is left consistent.
- Label the claim: Demonstrated (persisted invariant violation, repeatable), Inferred (inconsistent responses, state unverified), Unproven (theoretical window).

## When to Mark N/A
- The operation is idempotent by design and enforced by the datastore (unique constraint, idempotency key, atomic update), confirmed by persisted-state checks.
- No state-changing, value-bearing or limit-enforcing operations exist in the area under test.
- All critical operations are serialized through a queue or single-writer mechanism, confirmed by behavior.
- Testing would require load that exceeds the rules of engagement or risks availability: record as "Not tested (RoE limits)".
- The target is a read-only or static site.
