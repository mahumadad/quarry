---
name: waf-fingerprint
description: >
  Identify whether a WAF/CDN edge sits in front of the target, which vendor it is, and which
  generic bypass techniques apply to that vendor — via wafw00f and manual response-header/
  behavioral analysis. Use right after active-recon confirms liveness and before port-scan/
  hunt-* skills invest effort assuming they're reaching the real origin. Do NOT use for general
  technology fingerprinting (framework, CMS, server) — that's tech-stack-fingerprint; this
  skill is specifically about the WAF/edge layer and whether it is intercepting traffic before
  reaching the real backend.
metadata:
  type: recon
  phase: recon
  tools: [wafw00f, curl, nmap]
depends_on: [active-recon]
feeds_into: []
---

## Signals

- `active-recon` confirmed a host answers on 80/443 but is fronted by CDN/cloud-LB infra (per
  `active-recon`'s own gotcha about CDN-fronted hosts answering for the edge, not the origin).
- A request with an intentionally suspicious payload (test SQLi/XSS string) returns a
  generic-looking block page or an unusual status code (403, 406, 429, 503) instead of the
  app's normal error handling.
- Before starting any hunt-* skill that sends attack-shaped payloads — knowing the WAF vendor
  up front changes payload encoding strategy and avoids burning attempts on techniques that
  vendor already blocks by default.
- Response headers show vendor-identifying artifacts (`cf-ray`, `x-sucuri-id`, `x-akamai-*`,
  `server: cloudflare`).

## Prerequisites

- Confirmed-live target from `active-recon`.
- `opsec-discipline`'s rate policy — probing for WAF behavior still counts as live traffic to
  the target and should stay within agreed timing/concurrency.

## Methodology

1. **Run wafw00f first** for a fast, signature-based vendor identification pass:
   ```bash
   wafw00f https://example.com -a          # -a: check all signatures, don't stop at first match
   ```
   A single run can be inconclusive (modern WAFs minimize fingerprintable differences) — treat
   a "no WAF detected" result as provisional, not conclusive, and continue to manual checks.

2. **Check response headers for vendor artifacts directly**, since many WAF/CDN vendors leave
   identifiable headers even when wafw00f's signatures don't trigger:
   ```bash
   curl -s -I https://example.com/ | grep -iE "cf-ray|x-sucuri|x-akamai|x-cdn|server|x-iinfo|x-waf|x-denied-reason"
   ```

3. **Send a deliberately suspicious (but harmless) payload and observe the block behavior**,
   since the block page/status itself is often vendor-specific even when headers are
   scrubbed:
   ```bash
   curl -s -i "https://example.com/?id=1' OR '1'='1" -o /dev/null -w "%{http_code}\n"
   curl -s -i "https://example.com/?x=<script>alert(1)</script>" -o /dev/null -w "%{http_code}\n"
   ```
   Compare the blocked response's body/headers/status against a clean baseline request —
   a distinct block page, a specific ray/trace ID header, or a characteristic status code
   (commonly 403, but some vendors use 406/429/503) confirms interception before the origin.

4. **Differentiate WAF-layer blocking from application-layer validation.** A clean baseline
   request and a payload request that differ only in HTTP status (both otherwise identical
   response structure) suggest app-level handling; a response that looks structurally
   *different* (different server header, different body entirely, a vendor-branded block page)
   confirms an intermediary WAF, not the app itself, did the blocking.

5. **Test TLS/behavioral fingerprinting as a cross-check** where header-based detection is
   inconclusive — some vendors are identifiable by TLS handshake characteristics or by timing
   differences between blocked and passed requests:
   ```bash
   nmap -p443 --script ssl-cert,http-waf-detect,http-waf-fingerprint example.com
   ```

6. **Once a vendor is identified, note the generic bypass techniques known for that vendor**
   (case variation, encoding tricks, HTTP parameter pollution, chunked transfer, alternate
   content-types) as hypotheses for later hunt-* skills to try if a direct payload gets
   blocked — but do not run exploitation-grade bypass attempts here; this skill identifies the
   WAF, it doesn't defeat it. Record the vendor and suspected bypass angle for the relevant
   hunt-* skill to pick up.

7. **Record whether the WAF appears to be in block mode or detect/log-only mode.** A payload
   that returns 200 with no visible effect but logs server-side (unobservable from outside)
   is a different situation than one that's actively blocked — note explicitly which was
   observed, don't assume block mode just because a vendor was identified.

## Tooling

`wafw00f -a`, `curl -I`/`curl -i` for header and block-page comparison, `nmap --script
ssl-cert,http-waf-detect,http-waf-fingerprint`.

## Validation gate

- [ ] WAF presence/absence stated with evidence (header artifact, distinct block response, or
      explicit "inconclusive after both automated and manual checks") — never assumed from a
      single wafw00f run alone.
- [ ] If a WAF is present, the vendor (or "unidentified vendor, confirmed present") is recorded
      for every subsequent hunt-* skill to reference before assuming raw payloads will land.
- [ ] Block-mode vs. detect/log-only-mode distinction is stated, not assumed.
- [ ] Probing stayed within `opsec-discipline`'s rate policy — this skill sends several
      deliberately suspicious requests, which is exactly the kind of traffic that policy
      governs.

## Gotchas

- "No WAF detected" from wafw00f alone is a common false negative — many enterprise WAFs
  (especially custom/cloud-native rule sets) don't match any public signature; always pair
  with the manual payload/header check before concluding there's no WAF.
- A CDN being present (Cloudflare, Akamai, Fastly) does not automatically mean WAF rules are
  active — some clients use the CDN purely for caching/performance with the WAF module
  disabled; don't conflate "fronted by a CDN vendor" with "protected by that vendor's WAF."
- Aggressive WAF-bypass probing (many payload variants in quick succession) can itself trigger
  IP-based blocking/rate-limiting that then reads as "everything is blocked" — pace probing per
  `opsec-discipline`, and don't mistake a self-inflicted IP ban for WAF behavior.
- A WAF blocking the obvious test payload does not mean the underlying vulnerability doesn't
  exist — it means the direct, unencoded PoC needs a bypass technique before the hunt-* skill
  can demonstrate it; never report "not vulnerable" purely because the first naive payload was
  blocked.
- Origin IP exposure (via historical DNS, SPF/MX records, or a misconfigured subdomain
  bypassing the CDN) can let later testing skip the WAF entirely — if found, note it, but any
  direct-to-origin testing needs the same scope confirmation as any other asset per
  `scope-discipline`.
