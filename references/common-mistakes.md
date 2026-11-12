# Common Mistakes — Injected Into All Agents

These are the most frequent errors in AI-assisted pentesting. Every agent
MUST be aware of these. Violating any of them is grounds for finding KILL.

## Top 15 Mistakes

### 1. Fingerprint ≠ Confirmed
Detecting a technology version is not confirming a vulnerability. `Server:
Apache/2.4.49` means Apache 2.4.49 is running, NOT that CVE-2021-41773 is
exploitable. The version may be patched, the vulnerable module may be
disabled, or the configuration may not be affected. **Rule:** version
detection → hypothesis → trigger attempt → confirm or kill.

### 2. Scanner Output ≠ Finding
Nuclei/Nikto/Nessus templates have false positive rates of 30-70% depending
on the template. A scanner hit is a LEAD, not a FINDING. **Rule:** every
scanner result must be manually verified with a targeted request before
registering as a finding.

### 3. Webpack-Stripped Bundles Miss 60-90% of API Surface
Minified JS bundles from webpack/vite/esbuild often strip dead code,
tree-shake unused endpoints, and obfuscate route names. Never claim
"exhaustive JS analysis" from minified bundles alone. **Rule:** combine
JS analysis with wayback URLs, API docs probing, and parameter discovery.

### 4. Probabilistic Chains Claimed As Reproducible
Race conditions, timing attacks, and TOCTOU chains that work "sometimes"
must report their success rate over multiple attempts (minimum 5-10 runs).
"It worked once" is not reproducible. **Rule:** chain PoC must include
success rate and methodology for consistent reproduction.

### 5. Reflected Input ≠ XSS
Input reflected in a response is NOT XSS until script execution is
demonstrated in a browser context. Filters, CSP, encoding, and context
(HTML attribute vs. JS string vs. URL) all affect exploitability. **Rule:**
XSS finding requires: payload executes in browser + bypasses any active
defenses + demonstrated in a realistic scenario.

### 6. Internal IP/Path Disclosure Overclaim
Leaking `10.0.1.5` or `/var/www/html/app/` in error messages is INFO, not
MEDIUM. Internal IPs are only useful if you can reach them (SSRF chain).
Paths are only useful if you can traverse them (LFI chain). **Rule:**
info-disclosure findings must state what an attacker gains from this specific
information in context.

### 7. SSRF Without Impact Demonstration
Making a server connect to your Burp Collaborator proves SSRF exists. It
does NOT prove impact. **Rule:** after confirming SSRF, immediately test:
cloud metadata (169.254.169.254), internal services (localhost ports), and
file read (file://) — the impact determines severity, not the existence.

### 8. IDOR Between Own Accounts ≠ IDOR
Testing IDOR by accessing your OWN other test account proves the API doesn't
validate ownership, but the severity depends on WHAT data is exposed.
Accessing your own profile via another ID is a different severity than
accessing another user's PII/financial data. **Rule:** IDOR findings must
specify exactly what data/actions are exposed to unauthorized users.

### 9. Expired/Rotated Tokens Claimed As Valid
JWTs or API tokens captured during testing may expire or rotate. A PoC that
works with a token from 3 hours ago but not with a current token is not a
valid finding. **Rule:** PoC must work with CURRENT credentials/tokens at
time of submission.

### 10. Confusing Test Environment Behavior With Production Vulns
Staging/dev environments often have debug modes, relaxed CORS, disabled auth,
and verbose errors that don't exist in production. **Rule:** findings on
non-production environments must be verified against production behavior
(or clearly labeled as staging-only with reduced severity).

### 11. Assuming Impact Without Proof
"An attacker COULD use this to..." is a hypothesis, not a finding. Common
overclaims: "could lead to RCE" (without executing code), "could lead to
account takeover" (without taking over an account), "could lead to data
breach" (without accessing data). **Rule:** use evidence tags —
Demonstrated (PoC works), Inferred (partial evidence), Unproven (hypothesis).

### 12. Duplicate Findings Disguised As Separate Vulns
The same root cause (e.g., missing input validation) across 14 endpoints is
ONE finding with 14 affected endpoints, not 14 findings. **Rule:** normalize
parameterized endpoints (`/api/users/{id}`) and group by root cause before
registering.

### 13. Ignoring WAF/CDN Layer
A finding that works with `curl -k` but not through the actual WAF/CDN is
not exploitable in practice. Cloudflare, Akamai, and similar services block
many attack patterns. **Rule:** verify findings through the same path a real
attacker would use.

### 14. Testing Out-of-Scope Assets
Subdomains, IP ranges, and third-party services that look related but aren't
in scope. A vulnerability on `blog.target.com` hosted on WordPress.com is a
WordPress.com finding, not a target finding. **Rule:** verify scope for
EVERY asset before testing. When in doubt, ask the operator.

### 15. Not Checking the Never-Submit List
Common non-findings that waste everyone's time: missing headers alone, self-
XSS, open redirect alone, logout CSRF, version disclosure alone, CORS
wildcard without credentials. **Rule:** check references/never-submit.md
before registering ANY finding.
