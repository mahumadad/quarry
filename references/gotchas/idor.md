# Gotchas: Insecure Direct Object Reference / Broken Object Level Authorization (IDOR/BOLA)

## Common False Positives
- Object belongs to the same user or tenant: you changed the ID but it resolves to a resource you own, or you are accessing public data by design.
- Resource is intentionally public or shareable (public profile, shared link, published document): no authorization boundary exists.
- Response is 200 with an empty body, generic template, or `{"data": null}` instead of the victim's data.
- Cached response from your own earlier request is replayed (CDN/browser cache), not fresh data for the new ID.
- Sequential or guessable IDs alone: predictable identifiers are not a vulnerability if authorization is enforced. Enumeration without access is a hardening note.
- Test accounts that share an organization, role or group, so access is legitimate. Confirm the two accounts are in different tenants/permission scopes.
- Admin or privileged account used as the "attacker": it is expected to see other users' objects.
- 403/404 differences used to claim "enumeration" when the app returns 404 for both missing and forbidden (properly uniform) or leaks only trivially.
- Read-only metadata that is already exposed elsewhere (e.g. user IDs in public feeds).

## Overclaim Traps
- "Mass data breach" from one accessible record: state exactly what was accessed and extrapolate only with a verified enumeration rate and ID space.
- Claiming write/delete IDOR after proving read only (or vice versa). Each HTTP method and each field needs its own proof.
- Rating as Critical when the exposed object contains no sensitive data (public-ish settings, UI preferences).
- Treating mass assignment or role escalation (BFLA) as IDOR; they are different classes (function-level vs object-level).
- Claiming PII exposure without showing the fields returned; redact and describe categories.
- Reporting each endpoint of the same missing ownership check as separate Critical findings without noting the shared root cause.
- Assuming UUIDs make it safe or exploitable: if you cannot obtain another user's UUID, demonstrate how (leak elsewhere) or downgrade.

## Minimum Proof Required
- Two distinct accounts (A = attacker, B = victim) in different tenants/roles, with account identifiers recorded.
- Request made as A referencing an object owned by B, with full request and response, and the same object fetched legitimately as B for comparison (content matches).
- Evidence that the server, not the client, performed the access: valid session of A only, no B token or cookie.
- For write/delete: before/after state of B's object, using test data created for the purpose. Never modify or delete real customer data.
- Note how B's object ID was obtained (enumeration, leak in another response, predictable pattern).
- Sensitive values redacted in the report; keep full evidence in the engagement vault.

## When to Mark N/A
- Authorization is enforced server-side on every object access and cross-account requests consistently return 403/404 with no data.
- Resources are public by design and contain no user-restricted fields.
- Only one account or role was available, so the test could not be performed: mark "Not tested (single account)".
- The application has no per-user or per-tenant object model (single-user internal tool).
