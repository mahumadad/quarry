---
name: saml
description: >
  Attack SAML 2.0 single sign-on: XML Signature Wrapping (XSW), signature stripping/exclusion,
  assertion replay, NameID comment injection, signature-vs-parser discrepancies, RelayState as
  open redirect, and manipulated ACS/metadata. Use when the target authenticates via SAML (a
  SAMLResponse/SAMLRequest in requests, an ACS endpoint, IdP metadata, or identity-map flagged
  SAML SSO).
  Keywords: saml, xml signature wrapping, xsw, assertion, signature stripping, saml replay,
  nameid comment injection, relaystate open redirect, acs, idp metadata, sso bypass.
  Do NOT use for OAuth2/OIDC flows — use oauth. Do NOT use for JWT bearer tokens — use jwt.
  Do NOT use for generic XXE outside a SAML message — use xxe (SAML XXE lives there).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-347, CWE-290, CWE-287]
  mitre_attack: [T1606.002]
  tools: [saml-raider, burp, python, xmlsec]
depends_on: [identity-map, session-context]
feeds_into: [chain-analysis, chain-auth-to-takeover]
chains_with: [auth-bypass, xxe, open-redirect, jwt]
---

## Signals

- A `SAMLResponse` / `SAMLRequest` parameter (base64, often deflated) in requests, an Assertion
  Consumer Service (`/acs`, `/saml/consume`, `/sso/saml`) endpoint, or IdP metadata XML reachable.
- `identity-map` recorded SAML SSO as an authentication mechanism, or login redirects to an IdP
  and posts an XML assertion back to the SP.
- A `RelayState` parameter carried through the SSO round-trip.

## Prerequisites

- The ability to capture a *valid* SAMLResponse for a provisioned test identity (log in once and
  intercept the assertion POST to the SP's ACS).
- Confirmation that both the SP and IdP are in scope. A third-party IdP (e.g. a shared commercial
  SSO tenant) is not in scope merely because the SP uses it — stop and confirm before touching it.
- `SAML Raider` (Burp extension) or an XML toolkit; keep the captured assertion as the baseline.

## Methodology

1. **Capture and decode the baseline assertion.** Intercept the ACS POST, URL-decode, base64-
   decode (and inflate if deflated) the `SAMLResponse`. Identify the signed element (Response vs
   Assertion), the `<ds:Signature>` location, `NameID`, `Conditions` (`NotOnOrAfter`,
   `AudienceRestriction`), and `InResponseTo`.

2. **Signature stripping / exclusion.** Remove the `<ds:Signature>` entirely (or submit an
   unsigned assertion) and replay. An SP that accepts an unsigned or signature-removed assertion
   trusts attacker-controlled identity data outright:
   ```
   # SAML Raider: "Remove Signatures", then edit NameID -> victim, re-encode, replay to ACS
   ```

3. **XML Signature Wrapping (XSW).** Keep the original signed element so the signature still
   verifies, but add a second, attacker-controlled assertion/element that the application logic
   reads instead. Walk the standard XSW permutations (XSW1–XSW8: wrap at Response vs Assertion
   level, forged element before/after the signed one, `Id`/reference mismatches). SAML Raider
   automates all eight; the finding is any permutation where the signature check passes but the
   SP consumes the forged `NameID`.

4. **Signature-vs-parser discrepancy (comment injection).** If the SP canonicalizes/verifies with
   one XML library but reads `NameID` text with another, inject an XML comment to split the value:
   `admin@victim.com<!---->.evil` — the verifier sees one string, the consumer may read
   `admin@victim.com`. Test comment, CDATA, and nested-element splits of the `NameID`.

5. **Assertion replay / condition bypass.** Replay a captured valid assertion after its
   `NotOnOrAfter`, to a different `AudienceRestriction`, or without a matching `InResponseTo`, to
   check whether the SP enforces single-use, audience, timing and request-binding.

6. **RelayState open redirect.** Set `RelayState` to an external URL and complete SSO — if the SP
   redirects there post-login, that is an open redirect in the auth flow (phishing / token
   leakage vector). Cross-reference `open-redirect`.

7. **Manipulated metadata / ACS.** Where SP or IdP metadata is editable or dynamically fetched,
   test whether a forged `AssertionConsumerServiceURL` or injected IdP metadata redirects the
   assertion to an attacker ACS. Gate any change to stored metadata with the operator.

## Tooling

- **SAML Raider** (Burp) — XSW permutations, signature removal/editing, certificate swaps.
- `xmlsec1` / python `signxml` / `lxml` — manual canonicalization and signature inspection.
- Burp Decoder / a small script — base64+inflate round-trip of `SAMLResponse`.

## Payloads & Detection Patterns

Guía de caza sobre el mensaje SAML. Una familia por defecto de verificación/consumo; la prueba es
siempre que el SP *consume* la identidad forjada (sesión como el `NameID` víctima), no que el XML parseó.

| Categoría | Shape | Propósito |
|---|---|---|
| Signature stripping/exclusion | Remover `<ds:Signature>` entero o enviar assertion sin firma | SP que acepta identidad no firmada confía datos del atacante |
| XML Signature Wrapping (XSW1–8) | Mantener el elemento firmado + clonar assertion forjada antes/después, mismatch de `Id`/reference | Firma verifica sobre el original, la app lee el `NameID` forjado |
| Comment/CDATA injection en NameID | `admin@victim.com<!---->.evil`, split por CDATA o nested-element | Verifier ve una string, el consumer lee la truncada |
| Assertion replay / condition bypass | Reusar assertion tras `NotOnOrAfter`, distinto `AudienceRestriction`, sin `InResponseTo` | `single-use`/audience/timing/request-binding no enforced |
| RelayState open redirect | `RelayState=https://evil` llevado por el round-trip | Redirect post-login (phishing / fuga de token) |
| Manipulated ACS/metadata | Forjar `AssertionConsumerServiceURL` o inyectar IdP metadata | Desviar la assertion a un ACS atacante (**human-gate**) |
| Certificate swap | Re-firmar con cert propio + swap del `X509Certificate` en `KeyInfo` | Funciona si el SP no fija el cert del IdP esperado |

Surface signals que delatan la clase antes de probar:
- `SAMLResponse`/`SAMLRequest` base64 (a menudo deflate) y endpoints ACS (`/acs`, `/saml/consume`).
- `RelayState` arrastrado por el round-trip SSO.
- Firma a nivel Response vs Assertion — define dónde aplican las permutaciones XSW.
- Si el parser de la assertion también resuelve entidades externas → exfil OOB vía `xxe` (gate OOB por token ahí).

```bash
# Round-trip del SAMLResponse para inspección (decode base64 + inflate)
echo "$SAMLRESPONSE" | python3 -c 'import sys,base64,zlib,urllib.parse; \
d=base64.b64decode(urllib.parse.unquote(sys.stdin.read().strip())); \
print(zlib.decompress(d,-15).decode(errors="replace") if d[:1]!=b"<" else d.decode(errors="replace"))'
# luego en SAML Raider: Remove Signatures / XSW1-8 / editar NameID -> victim -> re-encode -> replay a ACS
```

## Bypass Techniques

Agrupadas por el control de confianza del SP que evaden; la nota es la condición que la delata.

| Filtro evadido | Técnica | Notas |
|---|---|---|
| Firma requerida | Strip total / assertion unsigned | SP que no exige firma consume la identidad editada |
| Verificación de firma (wrapping) | XSW manteniendo el elemento firmado intacto | Verifier valida el original, la app lee el forjado (mismatch `Id`/XPath) |
| Un solo parser XML | Comment/CDATA/nested split en `NameID` | La verify-lib y la read-lib canonicalizan distinto |
| Replay cache / timing | Reusar tras expiry, distinto `AudienceRestriction`, sin `InResponseTo` | IdP-initiated omite `InResponseTo` por diseño — no inflar como finding |
| Allow-list de RelayState | URL externa en `RelayState` | Redirect post-auth sin allow-listing |
| Pinning del cert del IdP | Swap del `X509Certificate` en `KeyInfo` + re-firma | Solo si el SP confía el cert embebido en vez del esperado |

## Root Causes

- The SP validates the signature over one element but trusts data from a different (unsigned or
  wrapped) element — the core XSW defect.
- Signature verification and assertion parsing use different XML libraries with different
  canonicalization/comment handling.
- Missing enforcement of single-use (`InResponseTo`/replay cache), `NotOnOrAfter`, and
  `AudienceRestriction`.
- `RelayState` treated as a trusted post-auth redirect target without allow-listing.

## Validation Gate (minimum proof)

- A forged or wrapped assertion that the SP *accepts* and that results in authentication as a
  different identity (session established as the victim `NameID`), with the manipulated
  `SAMLResponse` and the resulting authenticated session captured.
- For comment injection: proof the SP read the truncated/split `NameID` (logged in as the shorter
  identity) while the signature still verified.
- Mitigating findings (e.g. unsigned accepted but assertion still audience/time-bound) recorded as
  such, not inflated to full bypass.

## Gotchas

- **Scope the IdP explicitly.** Replaying or forging assertions against a third-party IdP's own
  infrastructure is out of scope unless the client owns that IdP tenant and it is named in scope.
- **Common N/A:** the SP rejects the stripped/wrapped assertion and enforces audience + timing —
  that is the control working; XSW failing across all eight permutations is a clean result, record
  it as coverage.
- **Overclaim trap:** a signature that still verifies after you edited an *unsigned* field is not
  a bypass by itself — you must show the SP *consumed* the attacker value (authenticated as the
  victim), not merely that the message parsed.
- Do not paste full captured assertions (they may contain real identity material and signatures)
  into the report body — store them in the evidence vault and reference them.
- IdP-initiated SSO often skips `InResponseTo` by design — absence of request-binding there is not
  automatically a finding; judge against the deployment's SSO mode.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Identity choice** — Can you authenticate as an arbitrary `NameID` (including an admin), or
   only as a fixed/other test identity?
2. **Privilege level** — Does the forged identity map to a higher-privilege role in the SP?
3. **Replay window** — Is a captured assertion reusable (no single-use cache), and for how long?
4. **RelayState** — Does the SSO flow leak to an attacker-controlled redirect target?
5. **Parser split** — Does signature-vs-consumer library disagreement generalize beyond `NameID`
   to other trusted attributes (groups/roles)?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- saml → **chain-auth-to-takeover** when a forged `NameID` yields an admin session.
- saml + **xxe** when the SAML parser also processes external entities in the assertion.
- saml + **open-redirect** via `RelayState` for post-auth token/phishing delivery.
- saml → **jwt** when the SP mints a JWT session from the (forged) assertion — pivot to token
  attacks on the issued session.
