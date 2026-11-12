---
name: osint
description: >
  Open-source intelligence beyond DNS/web surface: Shodan/Censys device search, social
  media and employee enumeration, and checking for leaked-credential exposure. Use early
  in recon alongside passive-recon, to characterize the organization's exposed footprint
  and people, not just its domains. Do NOT use for domain/subdomain-specific DNS work —
  that's passive-recon/dns-enumeration; this skill is org- and people-centric.
metadata:
  type: recon
  phase: recon
  tools: [shodan, censys, theHarvester, linkedin, haveibeenpwned]
depends_on: [scope-discipline]
feeds_into: [email-harvesting, github-dorking, subdomain-discovery]
---

## Signals

- Need to know what the organization exposes on the public internet beyond the known web app
  (IoT, exposed management interfaces, misconfigured databases).
- Need employee names/roles for phishing-susceptibility assessment or credential-stuffing risk.
- Checking whether the org's domain/employees appear in known breach dumps.

## Prerequisites

- Org name and domain(s) confirmed in scope.
- Shodan/Censys API keys provisioned if using their CLI/API (free tiers are rate-limited and
  often insufficient for a real engagement).

## Methodology

1. Shodan search for the organization's exposed infrastructure — by org name, by domain,
   and by discovered IP ranges:
   ```bash
   shodan search "org:\"Example Corp\""
   shodan search "hostname:example.com"
   shodan host 1.2.3.4
   shodan search "net:1.2.3.0/24"
   ```
2. Censys as a complementary/cross-check source (different crawl footprint than Shodan,
   often surfaces different hosts):
   ```bash
   censys search 'services.certificate.names: example.com' --index-type hosts
   censys view 1.2.3.4
   ```
3. Look specifically for commonly-misconfigured exposed services surfaced by either tool:
   exposed databases (Elasticsearch, MongoDB, Redis with no auth), exposed management
   interfaces (Jenkins, Kibana, admin panels), and exposed IoT/OT devices:
   ```bash
   shodan search "org:\"Example Corp\" product:MongoDB"
   shodan search "org:\"Example Corp\" port:9200"      # Elasticsearch
   shodan search "org:\"Example Corp\" product:Jenkins"
   ```
4. Employee enumeration via theHarvester (pulls from search engines, LinkedIn, PGP key
   servers, and more in one pass):
   ```bash
   theHarvester -d example.com -b all -l 500 -f harvester-results
   ```
5. Manual LinkedIn reconnaissance for org structure, tech stack hints (job postings
   mentioning specific tools/frameworks), and employee names for the email-harvesting
   pattern work:
   ```
   site:linkedin.com/in "Example Corp"
   site:linkedin.com/in "Example Corp" "security" OR "IT" OR "DevOps"
   ```
   Job postings are a particularly high-value and under-used source — they often name exact
   internal tools, cloud providers, and even internal project codenames.
6. Breach/leak exposure check for the organization's domain and any specific identified
   employee emails:
   ```bash
   curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/example.com" \
     -H "hibp-api-key: $HIBP_KEY"
   ```
   Note: HIBP's domain-search API requires a paid key and proof of domain ownership for the
   client — use the client's own key/account for this, not a personal one, and only with
   their authorization since it involves their employees' data.
7. Consolidate: org exposure list (Shodan/Censys hosts), employee list (theHarvester/LinkedIn),
   and breach exposure summary, feeding `email-harvesting` and `github-dorking`.

## Tooling

`shodan` CLI (`search`, `host`, `net:` filters), `censys` CLI, `theHarvester -b all`, manual
LinkedIn/job-board search, HaveIBeenPwned API (domain search requires client-owned key).

## Validation gate

- [ ] Every Shodan/Censys host cross-checked against `scope.txt`/org ownership before
      being treated as in-scope attack surface — org-name search can return hosts owned
      by unrelated third parties with similar names.
- [ ] Employee data handled per `opsec-discipline`'s data-handling rules — this is PII,
      store and transmit only through the client's designated secure channel.
- [ ] Breach-exposure checks run only with the client's own authorized access, not a
      personal API key against their domain without clear authorization for that specific check.

## Gotchas

- Org-name search on Shodan/Censys returns false positives from similarly-named orgs,
  shared hosting, and third-party SaaS the org merely uses — verify ownership per
  `scope-discipline` before scanning or reporting any of it.
- Employee enumeration output is personal data — treat retention/sharing with the same
  care as credentials or PII findings, per `opsec-discipline`.
- theHarvester's search-engine sources degrade/break frequently as providers change their
  anti-scraping measures — don't assume `-b all` actually hit every source; check per-source
  output counts.
- A breach-dump hit for an employee email doesn't mean the password is still valid — it's
  Inferred-tier risk context, not a demonstrated credential-stuffing finding until actually
  tested (and credential-stuffing testing needs its own explicit RoE sign-off).
