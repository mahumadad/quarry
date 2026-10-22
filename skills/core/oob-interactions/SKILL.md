---
name: oob-interactions
description: >
  Confirm blind vulnerabilities with out-of-band interaction tracking. Use whenever a
  payload's effect is NOT visible in the HTTP response: blind SSRF, stored/blind XSS,
  blind XXE, blind RCE/command injection, blind SQLi (DNS exfil), deserialization
  callbacks, log poisoning with async trigger. Manages unique correlation tokens via
  engine/oast.py so a callback is evidence-grade (Demonstrated), not background noise.
  Keywords: OAST, OOB, out-of-band, interactsh, Burp Collaborator, callback, blind,
  DNS exfiltration, correlation token, listener.
  Do NOT use for vulnerabilities whose effect is directly visible in the response.
metadata:
  type: core
  phase: hunting
  mitre_attack: [T1190, T1071.001, T1048]
  tools: [interactsh-client, curl, own-listener]
depends_on: [active-recon]
feeds_into: [finding-validation, evidence-hygiene]
chains_with: [ssrf, xxe, rce, deserialization, xss, sqli]
---

## Purpose

The plugin's anti-fabrication rules forbid reporting "could allow X". For blind
vulnerability classes, the ONLY way to reach `Demonstrated` is a received,
correlated callback. This skill is the discipline; `engine/oast.py` is the
machinery. Without OOB confirmation, blind findings cap at `Inferred`.

## When this skill is MANDATORY

- Blind SSRF — server fetches but response is not reflected (image re-encoding,
  webhook fire-and-forget, queued jobs).
- Stored XSS — payload lands in an admin panel / support inbox / log viewer you
  cannot see.
- Blind XXE — parser resolves entities but returns no content.
- Blind RCE — command runs but output is not returned (use `curl`/`nslookup` to
  your listener as the proof command).
- Blind/time-based SQLi escalation — DNS exfil (`LOAD_FILE`, `xp_dirtree`,
  `UTL_HTTP`) to prove actual execution instead of relying on timing alone.
- Deserialization — gadget chains that phone home instead of returning output.

## Methodology

1. **Get a callback host BEFORE injecting.** In order of preference:
   - `interactsh-client` (self-hosted for client-confidential engagements —
     public `oast.*` servers are shared infrastructure, treat as disclosure).
   - Burp Collaborator (if Burp MCP is connected).
   - Own listener: VPS with `python3 -m http.server` + access log, or
     `dnsmasq`/authoritative DNS logging for DNS-only vectors.
   Record which backend in the engagement notes — it goes in the finding evidence.

2. **Mint one token per injection attempt** via `OASTManager.new_token()`.
   Never reuse tokens across endpoints or vuln classes — correlation is the
   entire evidentiary value. Token goes as subdomain (`http://{token}.host/`)
   so DNS-only and full-HTTP callbacks both correlate.

3. **Inject, then poll with class-appropriate patience:**
   - Reflected/immediate vectors: wait 30s.
   - Stored vectors (XSS in support panel, webhook queues, cron-triggered
     fetchers): re-check at 10 min, and once more before writing the final
     report — late callbacks are common and must not be reported as gaps
     prematurely, nor as findings before they arrive.

4. **Correlate strictly.** `record_interaction()` only matches tokens this
   engagement minted. Public OAST servers receive constant internet background
   noise — an unmatched hit is NEVER evidence.

5. **Promote to evidence.** `evidence_record(token)` produces the evidence
   block (injected-at timestamp, callback timestamps, remote address, raw
   request). Attach it to the finding via `FindingsStore.add_evidence()` and
   tag `Demonstrated`. Record capture in the custody log.

## Correlation quality tiers (for the finding's evidence note)

| Tier | Signal | Weight |
|---|---|---|
| 1 | HTTP request received with unique token + expected remote_addr belonging to target infra | Full proof |
| 2 | HTTP request with unique token, source IP is a known egress proxy/NAT of target | Full proof (note the proxy) |
| 3 | DNS lookup only, unique token | Strong — but confirm the app actually fetched (some validators resolve-only; see hunt-ssrf gotchas) |
| 4 | Interaction without token match | Background noise — discard |

## Gotchas

- **DNS-only ≠ fetch.** Tier 3 alone is not enough for classes where a
  blocklist check resolves the hostname without issuing the request — pair
  with a second vector or downgrade to `Inferred`.
- **Egress proxies:** callbacks often arrive from corporate egress IPs, not
  the app server. Verify the source belongs to target infrastructure (their
  ASN, their cloud range) and document it.
- **WAFs may fetch your URL themselves** (link scanners, email gateways
  pre-fetching URLs). A hit seconds after submission from a security-vendor
  IP range is the WAF, not the app — check remote_addr and timing.
- **Never put client-identifying data in token URLs** — the URL may end up in
  target logs and (on public OAST servers) third-party infrastructure.
- **Self-host for confidential engagements.** Public interactsh servers can
  see your callbacks; for clients under NDA with data-residency requirements,
  self-host interactsh or use your own VPS listener.

## Chain Anchors

1. Callback received → was it HTTP or only DNS? Escalate DNS-only to HTTP proof.
2. HTTP callback → does the raw request reveal internal headers/tokens the
   server attaches (internal API keys, Authorization on webhooks)? That is an
   info-disclosure finding in its own right.
3. Confirmed blind primitive → retry with an internal target URL (SSRF→IMDS),
   a cookie-stealing payload (XSS→session theft), or a data-exfil DNS encoding
   (SQLi→data out) per the relevant hunt skill's chain anchors.
