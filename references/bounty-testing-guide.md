# Testing Quarry on Real Bug Bounties — Field Guide

What to look for in targets, how to ramp up complexity, and where
each tier exercises a different part of the plugin.

---

## Tier 1 — Validate the pipeline (first 2–3 engagements)

**Goal:** confirm `/quarry:engage` → `recon` → `map` → `hunt` →
`validate` → `report` runs end-to-end without breaking.

### What makes a good Tier 1 target

- SaaS with a **REST API** (JSON, standard auth), a web app with
  login/registration, and documented endpoints (Swagger/OpenAPI).
- Scope: `*.domain.com` (wildcard subdomain) — passive-recon and
  subdomain-takeover get exercised.
- **Public program** on HackerOne, BugCrowd, or YesWeHack with
  clear scope and reasonable response times.
- Technology: mainstream stack (Node/Express, Django, Rails, Spring,
  Laravel) — Quarry's skills are tuned for these.

### What you're testing in Quarry

| Capability | How to verify |
|---|---|
| `passive-recon` chain | wayback-urls.txt produced, jwt-in-urls.txt and token-in-urls.txt populated |
| `js-analysis` | JS endpoints extracted, historical diffing ran |
| `identity-map` | roles, auth tokens, and permission boundaries captured |
| `coverage.json` | every cell has a status, no `null` or `skipped` without reason |
| `finding lifecycle` | at least one finding goes DETECTED → CONFIRMED or KILLED |
| `seven-question-gate` | applied to 1+ finding, with the re-approach tag if killed |
| `report` | markdown and/or PDF generated, CVSS 4.0 scores present |

### Target sourcing

- HackerOne: filter by "launched last 30 days" + "web application" —
  new programs have more low-hanging fruit.
- BugCrowd: "VDP" (Vulnerability Disclosure Program) — no bounty
  pressure, good for calibration.
- YesWeHack: European programs, less competition from automation.

---

## Tier 2 — Test chains and coverage (engagements 4–8)

**Goal:** exercise chain-matrix, multi-role testing, and the
finding-checker adversarial review.

### What makes a good Tier 2 target

- **Multi-tenant SaaS** with at least 2 visible roles (admin/member,
  or org-admin/user/guest).
- **OAuth integration** (social login, SSO) — exercises `oauth` and
  `open-redirect` skills in composition.
- File upload functionality — exercises `file-upload` skill.
- Payment or subscription flow — exercises `business-logic` and
  `race-condition` skills.
- API with **versioned endpoints** (`/v1/`, `/v2/`) — older versions
  often have weaker validation.

### What you're testing in Quarry

| Capability | How to verify |
|---|---|
| `chain-analysis` | at least one chain discovered (e.g., IDOR → info-disclosure → account-takeover) |
| `broken-access-control` + `idor` | tested across role matrix, not just unauthenticated |
| `2fa-bypass` | half-auth session tested, settings-page-disable variant tried |
| `coverage breadth` | all 35+ vuln classes attempted before any depth pass |
| `defense registry` | blocked/WAF-filtered classes recorded, not silently retried |
| `finding-checker` | adversarial review run on at least one CONFIRMED finding |

### Complexity patterns to chase

1. **State machine bugs** — multi-step flows (checkout, onboarding,
   email verification) where skipping/reordering steps yields access.
2. **Cross-tenant data leaks** — IDOR where the object belongs to
   another organization, not just another user.
3. **OAuth token theft** — open-redirect chained with OAuth
   `redirect_uri` manipulation to steal `code` or `access_token`.
4. **Race conditions in payments** — double-charge, double-credit,
   or coupon-reuse via concurrent requests.

---

## Tier 3 — Push the limits (engagements 9+)

**Goal:** find the bugs that scanners can't — business logic,
framework-specific injection, second-order vulns.

### What makes a good Tier 3 target

- **Enterprise app with integration middleware** — AS2, EDI, ESB
  (Apache Camel, MuleSoft, Spring Integration). The RCE via
  framework-specific endpoint injection lives here.
- **GraphQL API** with introspection disabled — exercises blind
  enumeration and nested query abuse.
- **Microservices with internal APIs** — SSRF from one service to
  another's internal endpoints.
- **Apps with complex serialization** — Java (.war/.jar deployed),
  .NET (ViewState), PHP (session serialization).
- **Mobile API backends** — often have weaker validation than the
  web frontend, older API versions still active.

### What you're testing in Quarry

| Capability | How to verify |
|---|---|
| `endpoint understanding` | 4-question analysis done before every test |
| `JSON type confusion` (sqli) | `column::int` cast tested on sort/filter params |
| `framework-specific RCE` | Camel/Spring/Mule endpoint injection probed |
| `second-order injection` | storage→render paths tested for SQLi/XSS |
| `response-time profiling` | baseline timing captured before injection |
| `historical JS diffing` | Wayback snapshots fetched and diffed for secrets |
| `hypothesis journal` | documented before testing, not post-hoc |

### Where these targets live

- **HackerOne private programs** — once you have signal/reputation
  from Tier 1–2, private invites come for bigger targets.
- **Synack Red Team** — vetted platform with enterprise targets.
- **Intigriti** — European targets, often enterprise-grade.
- **Direct VDP of large companies** — many have `/.well-known/security.txt`.
- **Open-source projects** — GitHub Security Lab, audit the actual
  code (white-box exercises Quarry's source-review skills).

---

## What to prioritize by vuln class

Not all classes are equally likely to yield findings. Based on
industry data (OpenAI $817K program, HackerOne Top 10):

### High ROI — always test thoroughly

- **Broken access control / IDOR** — #1 most reported, often
  missed by scanners because it requires role context.
- **Information disclosure** — low-hanging, builds chain fuel.
- **XSS (stored > reflected > DOM)** — still common, especially
  in legacy code paths.
- **SQLi** — rare on main paths, but common on admin/internal
  endpoints and sort/filter params.

### Medium ROI — test when signals exist

- **SSRF** — only if the app fetches URLs or has webhook features.
- **2FA/MFA bypass** — only if the app has 2FA.
- **File upload** — only if upload exists.
- **Race conditions** — only if there's a financial or state-changing flow.

### Low ROI (but high impact when found)

- **RCE** — rare, but any confirmed RCE is critical severity.
- **Deserialization** — needs a Java/.NET target with a visible sink.
- **HTTP smuggling** — needs specific proxy configurations.

---

## Workflow per engagement

```
1. /quarry:engage   — define scope, aliases, budget
2. /quarry:recon    — passive first, active second
3. /quarry:map      — identity-map + endpoint inventory
4. Review map output — answer the 4 endpoint questions
5. /quarry:hunt     — breadth-first, all classes
6. /quarry:chain    — once ≥2 findings confirmed
7. /quarry:validate — adversarial review, dedup
8. /quarry:report   — generate deliverable
```

Between steps 5 and 6, check `coverage.json` — any class still at
`partial` or `inconclusive` deserves a second pass before chaining.

---

## Red flags that a target is too simple for Tier 2+

- Single-page app with no backend API (static site with a contact form).
- No authentication at all.
- Scope limited to a single domain with < 10 endpoints.
- No file upload, no payment, no multi-role access.

These are fine for Tier 1 but won't stress-test Quarry's chain
engine or coverage tracking.

## Red flags that a target is out of scope for Quarry

- Native mobile app only (no web/API surface).
- IoT/hardware without an HTTP-based management interface.
- Targets requiring physical access or social engineering.

Quarry's strength is web/API pentest — the entire skill tree is
built around HTTP request/response pairs.
