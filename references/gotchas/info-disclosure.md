# Gotchas: Information Disclosure

## Common False Positives
- Server or framework version in a `Server`, `X-Powered-By` or similar header with no known, applicable and verified vulnerability for that exact version and configuration. A version string alone is a hardening observation (informational), not a finding.
- Version strings that are fronted by a CDN, WAF or reverse proxy and do not reflect the backend; or deliberately spoofed banners.
- Public debug, health, status or metrics endpoints that are intentionally public and expose only non-sensitive information (uptime, build number, a "pong"). Distinguish from debug interfaces that leak configuration, environment variables, stack traces or internal hostnames.
- Debug or developer tooling reachable only in a development or staging environment that is out of scope or isolated from production data. Confirm the environment before reporting; do not assume.
- `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/` files listing paths: these are public by design. A listed path is not a finding unless the path itself is sensitive and accessible.
- Public API documentation (OpenAPI/Swagger, GraphQL introspection) on an API that is public by design. Exposure of the schema is a finding only when it reveals internal-only or unreleased functionality, or authentication is expected but absent.
- Email addresses, names or phone numbers that the organization publishes openly (contact page, WHOIS with privacy off by choice).
- Source maps or JavaScript containing publishable client identifiers (analytics keys, public API keys intended to be public, e.g. publishable payment keys). Verify the key's intended scope before reporting.
- Verbose errors that show generic framework messages without paths, queries, credentials or internals.
- Directory listing of intentionally public file repositories.
- Test or placeholder values (example.com addresses, dummy keys) mistaken for real secrets.

## Overclaim Traps
- Rating high/critical for a disclosed version or a technology fingerprint. Severity derives from demonstrated, exploitable impact, not from recon-grade data.
- Claiming "credentials exposed" without verifying the secret is real, valid and in use. Never validate secrets against third-party services beyond what the rules of engagement allow; for your target's own secrets, get operator approval before testing validity.
- Reporting stack traces as critical without showing sensitive content (credentials, SQL with data, internal topology).
- Claiming PII breach from a response that contains data about the tester's own account, test data, or public information.
- Treating exposed `.git`, backup or config files as critical without confirming the content is retrievable and sensitive; show what a minimal retrieval exposed, not the whole repository.
- Counting user enumeration as high when the information is already public or the response difference is negligible and rate limiting exists; assess exploitability honestly.
- Presenting cloud storage listing as sensitive without checking whether the objects are meant to be public.
- Inflating by listing every verbose header as a separate finding rather than one consolidated hardening finding.

## Minimum Proof Required
- The exact URL, request and response showing the disclosed data, with timestamp, and the environment (production vs non-production) confirmed.
- Classification of the data: what it is (credential, token, PII category, internal hostname, source code), and why it is sensitive in this context.
- For secrets: evidence of format and context, a statement of whether validity was verified (and how, with operator approval), and the privilege it would grant if valid. Redact the value in the report; keep the full artifact in the engagement vault.
- For PII: categories and approximate record counts observed; no bulk download. Minimum sample to prove exposure.
- Evidence the endpoint is reachable by the stated actor (unauthenticated, any authenticated user, internal only).
- For version disclosure: the specific, applicable CVE with a behavioral or configuration confirmation, otherwise classify as informational hardening.
- Label the claim: Demonstrated (sensitive data retrieved), Inferred (indicators of exposure), Unproven (version banner only).

## When to Mark N/A
- Responses contain only information that is public by design and none of it is sensitive in context.
- Debug or status interfaces return only non-sensitive operational information and are intended to be public.
- Detailed errors and debug features are disabled in production, confirmed by consistent generic error handling.
- Exposed endpoints are confirmed to belong to a non-production environment out of scope.
- Authentication gates all potentially sensitive endpoints and no unauthenticated exposure was found after reasonable coverage.
