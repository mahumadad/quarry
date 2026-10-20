---
name: dns-enumeration
description: >
  Direct DNS record enumeration against the target's authoritative name servers: all record
  types (A, AAAA, MX, NS, TXT, SRV, CNAME), zone transfer attempts, and DNSSEC checks. Use
  after passive-recon's candidate list exists, to fully characterize DNS configuration and
  attempt misconfigurations like open zone transfers. Do NOT use this for subdomain brute
  force/permutation — that's subdomain-discovery; this skill targets record-level detail and
  server misconfig on names you already have.
metadata:
  type: recon
  phase: recon
  tools: [dig, host, dnsrecon, dnsenum, fierce]
depends_on: [scope-discipline, passive-recon]
feeds_into: [subdomain-discovery, email-harvesting]
---

## Signals

- Need the full DNS record picture (mail setup, SPF/DMARC, service records) for a domain.
- Want to test whether a zone transfer is possible (frequently still open on misconfigured
  secondary name servers).
- Need to check DNSSEC deployment status.

## Prerequisites

- Target domain confirmed in scope (`scope-discipline`).
- NS records from `passive-recon`'s initial lookup.

## Methodology

1. Identify authoritative name servers, then query them directly (not public resolvers —
   authoritative answers are ground truth and may differ from cached public-resolver data):
   ```bash
   dig NS example.com +short
   dig A example.com @ns1.example.com
   ```
2. Pull every common record type against the authoritative server:
   ```bash
   for t in A AAAA MX NS TXT SRV CNAME SOA CAA; do
     echo "== $t =="; dig $t example.com @ns1.example.com +short
   done
   ```
3. Attempt a zone transfer against each authoritative NS — this is the single highest-value
   DNS misconfig check (dumps the entire zone if allowed):
   ```bash
   for ns in $(dig NS example.com +short); do
     echo "== $ns =="
     dig AXFR example.com @"$ns"
   done
   ```
   If any server returns full records instead of REFUSED/timeout, you have a confirmed
   finding — capture the full output as evidence per `finding-discipline`.
4. Automated full sweep with dnsrecon (combines record enumeration, AXFR attempts, and
   reverse lookups in one pass):
   ```bash
   dnsrecon -d example.com -a -t axfr,std,srv,brt
   ```
5. Check SPF/DKIM/DMARC TXT records (feeds `email-harvesting` and phishing-susceptibility
   assessment):
   ```bash
   dig TXT example.com +short | grep spf
   dig TXT _dmarc.example.com +short
   dig TXT default._domainkey.example.com +short
   ```
6. Check DNSSEC deployment:
   ```bash
   dig DNSKEY example.com +short
   dig DS example.com +short
   delv example.com                     # validates the chain if DNSSEC is deployed
   ```
7. Reverse DNS (PTR) sweep across any IP ranges in scope, to surface hostnames not found
   via forward lookups:
   ```bash
   for ip in $(seq 1 254); do dig -x 10.0.0.$ip +short; done
   ```

## Tooling

`dig` (`+short`, `AXFR`, `NS`, explicit `@server`), `host`, `dnsrecon -a -t axfr,std,srv,brt`,
`dnsenum`, `fierce --domain example.com`, `delv` for DNSSEC chain validation.

## Validation gate

- [ ] Queries sent to authoritative NS, not just cached public-resolver answers, for anything
      being reported as a finding.
- [ ] A successful zone transfer, if found, has full raw `dig AXFR` output saved as evidence.
- [ ] All discovered hostnames filtered against `scope.txt` before being handed to
      `subdomain-discovery`/active tools.

## Gotchas

- Zone transfer success is binary and loud evidence — capture it immediately, it's not
  reproducible forever (admins fix it fast once noticed).
- SPF/DMARC absence or weak policy (`p=none`) is Inferred-tier for phishing risk, not
  Demonstrated — it indicates exposure, it doesn't itself prove a successful spoof.
- DNSSEC `DNSKEY`/`DS` presence alone doesn't mean validation is enforced end-to-end —
  use `delv` or `dig +dnssec +cd` comparisons to confirm the chain actually validates.
- Reverse DNS sweeps across large ranges are slow and easy to rate-limit yourself into —
  batch with `xargs -P` carefully and respect `opsec-discipline` timing.
