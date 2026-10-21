# Never-Submit List

Findings that must be automatically KILLED — they are not vulnerabilities
and reporting them wastes operator time and damages credibility.

## Hard Rejects

These are NEVER findings regardless of context:

1. **Missing security headers alone** — HSTS, CSP, X-Frame-Options, etc.
   missing without demonstrated exploit. These are configuration notes, not
   vulnerabilities. (Exception: missing HSTS on a site handling credentials
   where you can demonstrate a MITM cookie theft scenario.)

2. **GraphQL introspection enabled alone** — Introspection is a feature.
   Only a finding if combined with exposed sensitive fields, broken access
   control, or DoS via nested queries.

3. **Self-XSS** — XSS that only fires in the attacker's own browser/session
   with no path to affecting another user. Requires demonstrated cross-user
   delivery path (CSRF, postMessage, clickjacking chain) to upgrade.

4. **Open redirect alone** — Only a finding when chained: OAuth redirect_uri
   abuse, phishing with token leak, or SSRF amplification. "User could be
   redirected to a phishing site" without demonstrated token theft is not
   accepted.

5. **SSRF with DNS resolution only** — Server makes a DNS query but no HTTP
   request to attacker-controlled infrastructure. Must demonstrate: HTTP
   callback, internal service access, or cloud metadata read.

6. **CORS wildcard (`*`) without credentials** — `Access-Control-Allow-Origin: *`
   without `Access-Control-Allow-Credentials: true` is by design and cannot
   leak authenticated data. Only a finding with `credentials: true`.

7. **Logout CSRF** — Forcing another user to log out has no security impact.

8. **Rate limiting absence alone** — Unless you demonstrate: credential
   stuffing success, OTP brute force, or resource exhaustion DoS. "No rate
   limit on login" without a working brute force is not a finding.

9. **Version disclosure alone** — `Server: nginx/1.21.0` or `X-Powered-By:
   Express` without a demonstrated exploit for that version. Version
   information is useful for the report's tech stack section, not findings.

10. **Email enumeration via timing/response differences on login** — Most
    programs explicitly accept this. Only a finding if the program's policy
    says otherwise AND there's no other way to determine valid accounts.

11. **SPF/DKIM/DMARC misconfiguration** — Unless you demonstrate actual
    spoofed email delivery to a target inbox (not your own). Configuration
    analysis alone is not a penetration test finding.

12. **Clickjacking on non-state-changing pages** — Framing a static info
    page has no impact. Only a finding on pages where user interaction
    (clicking a button, submitting a form) causes state change.

13. **Subdomain takeover claims on non-dangling CNAMEs** — The CNAME must
    actually point to an unclaimed resource. A CNAME to a functioning
    service is not a takeover. Verify: can you actually serve content?

14. **Token in URL** — Tokens in URL query strings are a concern (referer
    leakage, server logs), but only a finding if you demonstrate actual
    leakage to a third party via referer header or log access.

15. **Content spoofing / text injection** — Reflected text without script
    execution and without demonstrated phishing/confusion impact. "I can
    make the page say 'hacked'" is not a security impact.

## Soft Rejects (upgrade path exists)

These start as non-findings but CAN be upgraded with evidence:

| Initial finding | Upgrade condition |
|----------------|-------------------|
| Missing CSP | XSS found + CSP would have blocked it |
| Open redirect | + OAuth code/token leak via redirect_uri |
| Self-XSS | + CSRF or postMessage cross-user delivery |
| SSRF DNS-only | + HTTP callback or cloud metadata access |
| GraphQL introspection | + broken authz on sensitive queries/mutations |
| Info disclosure (version) | + working exploit for that exact version |
| Rate limit absent | + successful credential stuff or OTP brute |
| Email enumeration | + program policy explicitly forbids it |

## Application

- The `finding-validator` agent and `/pt:validate` command MUST check
  findings against this list before VALIDATED status.
- A finding on this list gets status KILLED with reason "never-submit: {item}".
- Operator can override with explicit justification — the override and its
  reasoning are recorded in the finding's metadata.
