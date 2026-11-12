# Gotchas: XML External Entity (XXE)

## Common False Positives
- JSON-only API: the endpoint rejects or ignores XML bodies, or returns 415/400 for an XML Content-Type. Changing the Content-Type header does not create an XML parser where none exists. Confirm a parser actually consumes the body.
- Server accepts an XML document and returns a generic success but never parses entities: the DTD is silently dropped or the document is only stored as a blob.
- Parser error that mentions "DOCTYPE" or "entity" because the parser is configured to disallow DTDs. A rejection message is evidence of a hardened parser, not of vulnerability.
- Internal entities (defined inline with literal values) are expanded, but external entities are blocked or not resolved. Internal entity expansion alone is not XXE; it may matter only for entity-expansion denial of service.
- Reflection of the submitted XML text in the response with no entity substitution.
- Out-of-band DNS or HTTP interaction caused by something else on the path (WAF, proxy, scanner infrastructure, email gateway, logging pipeline) rather than the application's XML parser. Correlate the source IP and timing with the target.
- DNS-only callback with no ability to read data or reach internal resources: it shows the parser resolves external references, but the exploitable impact still needs separate proof.
- Office documents, SVG or similar uploads that are only stored or served back, never parsed server-side.
- SOAP or SAML endpoints whose frameworks disable DTD processing by default in modern versions.

## Overclaim Traps
- "Arbitrary file read" claimed from a blind or DNS-only signal. Blind interaction proves outbound resolution at most, not file disclosure.
- Claiming SSRF-class internal access from a single outbound request without showing an internal resource was reached or its content returned.
- Rating Critical based on parser library and version alone. Version-based claims require a behavioral test because configuration (disallow-doctype, secure-processing flags, disabled external entities) decides exploitability.
- Reporting XXE for an endpoint that accepts XML only from authenticated administrators or trusted internal systems without noting the required privilege.
- Treating XInclude or XSLT processing as XXE without evidence they are enabled.
- Counting billion-laughs style entity expansion as data exposure. It is a resource-exhaustion issue and must not be tested against production without explicit operator approval.
- Assuming file content returned is from the server filesystem when it came from a test fixture, sandbox container or mock.

## Minimum Proof Required
- Evidence that an XML parser processes the request body: the endpoint accepts XML and a benign internal entity or well-formedness difference changes the response in a way only a parser would cause.
- Evidence that external entity resolution is enabled: either content from a harmless, operator-approved target is returned in the response (in-band), or an out-of-band interaction to infrastructure you control with a unique identifier arrives from the target's egress IP.
- For file disclosure: retrieval of a low-sensitivity, world-readable file agreed with the operator, returned in the response, with the exact request and response saved. Do not retrieve credentials, keys or customer data.
- For internal network access claims: a response (or timing/error difference) attributable to an internal resource, with the resource explicitly in scope.
- Parser, language and library identified from observed behavior, not only from headers.
- Control request showing the same flow without the external entity behaves differently.
- Label the claim: Demonstrated (in-band or verified OOB with source IP match), Inferred (resolution signal only), Unproven (accepts XML but no parsing evidence).

## When to Mark N/A
- The target exposes only JSON, form-encoded or protobuf endpoints, and no XML-bearing feature (SOAP, SAML, RSS import, document/SVG parsing, SSO metadata, SCIM/XML) was found after reasonable discovery.
- XML endpoints exist but the parser rejects DTDs outright and probing confirms no entity processing of any kind.
- XML processing happens entirely client-side or in a third-party service outside scope.
- File uploads are stored and served without server-side parsing, confirmed by behavior.
- The feature requires a privilege level the engagement does not grant: record as "Not tested (privilege)".
