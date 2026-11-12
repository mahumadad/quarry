---
name: chain-idor-to-mass-data
description: >
  Analyze and validate IDOR escalation chains: IDOR combined with absent/
  weak rate limiting enabling mass exfiltration, and IDOR combined with
  predictable/sequential identifiers enabling full enumeration of a
  resource space. Use when chain-analysis pairs a confirmed IDOR with
  state-map's rate-limit/throttling data or identity-map's identifier-
  scheme data.
  Do NOT use for a single-object IDOR with no demonstrated scale path —
  report that directly as a standalone IDOR finding without inflating it
  into a "mass exfiltration" claim it can't support.
metadata:
  type: chain
  phase: chaining
  tools: [burp, ffuf, turbo_intruder, curl]
depends_on: [chain-analysis, state-map, identity-map]
feeds_into: [finding-validation, report-writing]
chains_with: [chain-auth-to-takeover]
---

## Signals

- An IDOR is confirmed (object reference under attacker control returns another user's/
  tenant's data) and the identifier space is sequential, predictable, or enumerable.
- state-map noted an endpoint with no observed rate limiting, or a rate limit scoped in a way
  that doesn't actually stop bulk access (e.g. per-IP limit trivially rotated, or limit
  applies to writes but not the vulnerable read).
- The underlying resource, multiplied across the full identifier space, represents a
  genuinely larger harm than any single-record exposure (PII database, financial records,
  private messages).

## Prerequisites

- IDOR finding confirmed on at least one additional object beyond the tester's own (i.e.
  genuinely cross-user/cross-tenant access demonstrated, not just "the parameter looks
  changeable").
- Explicit operator authorization before any enumeration that will access many real users'
  records — this is the single highest-impact-to-real-victims chain pattern in this plugin
  and the human gate here is not optional.

## Methodology

1. **Characterize the identifier space.** From identity-map/state-map, determine whether IDs
   are sequential integers, time-ordered UUIDs (sortable, partially predictable), fully
   random UUIDs (not practically enumerable), or derived from guessable attributes (email
   hash, username-based). Only sequential/predictable/narrow-range spaces support an
   enumeration claim — fully random UUIDv4 spaces do not, no matter how real the single-
   object IDOR is.

2. **Confirm the access-control gap, not just the reference.** Verify the authorization
   check is actually missing/broken (not that you merely guessed a valid-looking ID that
   happens to be yours under a different representation) — request a specific other known
   object (e.g. a second test account you control) and confirm you receive *that* account's
   data, not ambiguous/generic data.

3. **Determine real rate-limit behavior.** Before any bulk test, probe with a small, bounded
   batch (e.g. 10-20 sequential requests) and observe: are requests throttled, blocked,
   CAPTCHA'd, or unrestricted? Record the actual threshold observed. Do not proceed to a
   larger batch without this data — it determines both the technical approach and the harm
   calculus for the next step.

4. **Scope a minimal-harm proof of mass-exfiltration risk.** The goal is to prove the
   capability exists, not to actually exfiltrate the full dataset. With explicit operator
   authorization, run a bounded sample sufficient to prove enumerability (e.g. confirm valid
   responses across a sample spanning the ID space, enough to extrapolate total addressable
   records) while capturing the minimum data necessary to prove the point (existence/count,
   not full record contents for records beyond your own test objects).

5. **Calculate and report the addressable scope, not the full content.** Report "N records
   are enumerable at an observed rate of R requests/sec with no effective throttling,
   implying the full dataset of ~M records could be exfiltrated in T time" as the impact
   statement — supported by the bounded sample — rather than actually holding or including
   real other users' data in the report.

## Validation gate

- The enumeration claim is backed by: (a) a confirmed access-control gap on a known test
  object, (b) an identifier-space characterization showing practical predictability, and
  (c) a bounded-sample rate-limit observation — all three, not any one alone.
- No deliverable (report, evidence file) contains bulk real-user data beyond what's strictly
  needed to prove the access-control gap (i.e. your own test objects plus counts/metadata for
  the sample, not full content dumps of other real users' records).
- Any batch beyond the small initial probe (step 3) requires the explicit operator sign-off
  described above, logged with what was authorized and when.

## Gotchas

- A sequential-ID IDOR against a resource type that turns out to require a *second* secret
  (e.g. ID + a per-record token) is not actually mass-enumerable — verify the full request
  requirement, not just the one parameter that looked interesting.
- Per-IP rate limiting is usually trivially bypassed with rotating source IPs/headers in a
  real attack — note this when assessing real-world risk, but do not actually perform
  IP-rotation evasion against production without specific authorization, since that
  materially increases load/risk on the target.
- "No rate limit observed in a 20-request sample" is evidence for that sample, not proof of
  no limit whatsoever — qualify the claim to what was actually tested.
- Tenant-scoped IDOR (cross-tenant in a multi-tenant SaaS) is generally higher severity than
  cross-user IDOR within one tenant — reflect this in how the chain is prioritized for
  write-up, per trust-map's tenancy boundary notes.
- Don't let the "mass" framing override the basic IDOR gotchas (see report/gotchas) — the
  underlying single-object proof still needs to meet the same evidentiary bar.
