# Gotchas: JWT Attacks

## Common False Positives
- Decoding a JWT and seeing claims in clear text. JWTs are signed, not encrypted, by design. Readable claims are not a vulnerability unless they contain secrets the token should not carry.
- Token with `alg: none` appears to be "accepted" because the response was 200 for an unauthenticated or public endpoint, or because the endpoint ignores the token entirely. Always compare against a request with no token at all.
- Server returns the same response regardless of token validity (cached page, public resource). The token may not be evaluated.
- A modified token accepted only by a client-side library or a debugging tool, while the actual API rejects it.
- `none` algorithm rejected with 401 but a different error message than a bad signature. Different messages do not mean the server accepts unsigned tokens.
- Algorithm confusion (asymmetric public key used as symmetric secret) claimed vulnerable because the public key is published at a JWKS endpoint. Publishing the public key is normal; exploitation depends on the verifier accepting the algorithm named in the token header.
- Weak-secret finding based on a cracked token from a different application or a sample token from documentation.
- Long expiry or missing `exp` claim reported as a vuln when the token is a deliberate long-lived API key with revocation support.
- Token stored in `localStorage` flagged as a JWT vulnerability. That is a storage/XSS-exposure concern, assessed separately.
- `kid`, `jku` or `x5u` header present, assumed injectable without testing whether the server honors untrusted values.

## Overclaim Traps
- "Authentication bypass" claimed after a token with an altered claim got a 200. You must show privileged data or actions that were gated and not available without the token or with a normal low-privilege token.
- Claiming algorithm confusion without showing the server accepts the attacker-chosen algorithm. Libraries pinned to an expected algorithm reject confusion attempts.
- Reporting a weak HMAC secret as Critical when only a crack of a captured token succeeded in a lab, but you did not show forged tokens being accepted by the target.
- Claiming signature not verified based on one library fingerprint without a behavioral test (tamper with payload, keep signature, observe rejection or acceptance).
- Treating missing audience (`aud`) or issuer (`iss`) validation as account takeover without a cross-service or cross-tenant replay that works.
- Claiming token replay as critical for short-lived tokens with server-side revocation without showing replay inside the validity window yields impact.
- Counting each endpoint that uses the same verification middleware as separate findings.

## Minimum Proof Required
- Baseline: capture of a valid token's behavior and a no-token and invalid-signature control for the same request, showing the protected endpoint truly enforces authentication.
- For signature bypass or `none`: a tampered or unsigned token accepted by a protected endpoint that rejects the no-token and bad-signature controls, with the privileged response shown (redacted).
- For algorithm confusion: demonstration that the verifier accepted a token signed under a different algorithm class than intended, using only keys that are public or yours.
- For weak secret: forged token (claims you chose, using a test identity) accepted by the target. Cracking offline alone is Inferred.
- For claim tampering (role, user ID, tenant): a before/after showing authorization changed using test accounts; never impersonate real users.
- For `kid`/`jku`/`x5u` abuse: proof that the server fetched or used an attacker-controlled key source (interaction logs on infrastructure you control) and accepted the resulting token.
- Record token header and payload (secrets redacted), the library or framework if observable, and the exact tamper performed.
- Label the claim: Demonstrated (forged or tampered token accepted for privileged action), Inferred (weak configuration indicators), Unproven (readable claims only).

## When to Mark N/A
- The application uses opaque server-side session identifiers and no JWTs are issued or accepted.
- JWTs are verified with a pinned algorithm and key, and tamper tests (payload change, signature strip, algorithm change) are all rejected.
- Tokens are encrypted (JWE) and not inspectable, and no token handling flaw is observable from the outside: record as "Not testable externally".
- JWTs are issued by a third-party identity provider whose verification is out of scope, and the application validates them via the provider's library with correct issuer and audience checks.
- No protected functionality depends on the token in the area under test.
