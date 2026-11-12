---
name: cryptographic-oracle
description: >
  Validate padding, decryption, validation and timing oracles in application cryptographic
  protocols using controlled samples and negative controls. Use for CBC padding errors,
  distinguishable token-validation failures, or measurable decryption/validation oracles;
  do not use for generic weak-cryptography observations without an exploitable interface.
metadata:
  type: hunt
  phase: hunting
  tools: [curl, python3, oast]
depends_on: [scope-discipline, opsec-discipline]
feeds_into: [finding-validation, chain-custom]
---

## Safety and scope

Use only tokens and test accounts issued for the engagement. Keep request counts low and within
the ROE: oracle testing can resemble credential attacks or availability testing. Bulk decryption,
forgery of another user's token and account takeover require separate explicit gates.

## Methodology

1. **Map the cryptographic boundary.** Identify token format, encoding, endpoint, identity,
   protocol version and where validation occurs. Do not infer CBC/PKCS#7 from token length alone.
2. **Build controlled baselines.** Capture unmodified valid input, malformed encoding, truncated
   input and random input of equal length. Record status, body, headers, timing and full artifacts.
3. **Test distinguishability.** Make one minimal, authorized modification at a time and compare
   padding/validation/MAC/decryption errors. Repeat interleaved valid and invalid controls so
   load balancing, rate limits and generic error pages cannot masquerade as an oracle.
4. **For timing hypotheses,** collect enough paired samples to report distributions and variance,
   alternate candidate ordering, and rerun on a separate baseline. A small average difference is
   `inconclusive`, not a demonstrated timing oracle.
5. **Demonstrate only the minimum impact.** A distinguishable error is a lead. Show a controlled
   padding/validation distinction, or a separately gated benign forgery/decryption on your own
   fixture, before claiming confidentiality or integrity impact.
6. **Record negative space.** If errors and timing converge across the defined samples, record the
   exact token family, endpoint, sample counts and artifact IDs. A different protocol/version is a
   new coverage cell, not covered by the old result.

## Evidence and gotchas

- Preserve raw inputs as hex/baseurl-safe artifacts plus exact request/response pairs and code used.
- Distinguish padding validity from MAC validity and from application-level authorization.
- Generic 400/500 differences are not enough; random-input and rate-limit controls are mandatory.
- Do not report “weak crypto” solely because CBC, ECB, RSA or SHA-1 appears; identify the actual
  protocol misuse and demonstrated consequence. Avoid destructive or high-volume oracle searches.
