---
name: email-security
description: >
  Email and domain hygiene checks: SPF, DKIM, DMARC, CAA, MTA-STS, DANE/TLSA,
  DNSSEC, and MX/TLS configuration. Passive checks that run with standard DNS
  tools — no traffic to the target's web app. Use during recon to surface email
  spoofing risk, missing authentication, and transport security gaps. Inspired by
  CVEngine's MailFail module and industry baselines (M3AAWG, NIST SP 800-177r1).
metadata:
  type: core
  phase: recon
  tools: [dig, nslookup, openssl, curl]
depends_on: [scope-discipline]
feeds_into: [finding-discipline]
---

## Signals

- Recon phase of any engagement where the target owns a domain that sends email.
- Client asks about phishing risk or email spoofing exposure.
- Passive recon discovers MX records for the target domain.
- Compliance check requested (PCI DSS, SOC 2, NIST, or GDPR data-in-transit).

## Prerequisites

- Target domain is in scope (`scope-discipline` cleared for DNS queries).
- DNS resolution works from the operator's machine (no firewall blocking UDP/53).

## Methodology

### 1. MX records and SMTP TLS

```bash
dig +short MX {domain}
```

For each MX host, verify STARTTLS support and certificate validity:

```bash
openssl s_client -starttls smtp -connect {mx_host}:25 -servername {domain} </dev/null 2>&1 | \
  grep -E "Verify return|subject=|issuer=|notAfter"
```

Findings:
- No MX records → domain may not send email (confirm before reporting).
- MX without STARTTLS → **medium** (email in transit is plaintext).
- Expired/self-signed MX certificate → **medium**.

### 2. SPF

```bash
dig +short TXT {domain} | grep "v=spf1"
```

Evaluate the record:
- **Absent** → **medium** (any server can send as the domain).
- `+all` → **medium** (SPF present but permits everything).
- `?all` → **low-medium** (neutral — no assertion, same as absent for receivers that honor it).
- `~all` (softfail) → acceptable if DMARC p=quarantine/reject backs it up; otherwise **low**.
- `-all` (hardfail) → correct.
- Count DNS lookups (each `include:`, `a:`, `mx:`, `redirect=` costs one; >10 → SPF permerror):
  ```bash
  # quick count — recursive resolution needed for accurate count
  dig +short TXT {domain} | grep -o 'include:\|a:\|mx\|redirect=' | wc -l
  ```

### 3. DKIM

No way to enumerate all selectors — probe common ones:

```bash
for sel in default google selector1 selector2 k1 k2 dkim s1 s2 mail; do
  echo -n "$sel: "
  dig +short TXT "${sel}._domainkey.{domain}" 2>/dev/null || echo "(none)"
done
```

For each found selector, check key length:

```bash
dig +short TXT {selector}._domainkey.{domain} | \
  sed 's/" "//g;s/"//g' | grep -oP 'p=\K[^;]+' | \
  base64 -d 2>/dev/null | openssl rsa -pubin -inform DER -text -noout 2>/dev/null | \
  head -1
```

Findings:
- No DKIM selectors found among common names → **medium** (Inferred — may use a
  non-standard selector; note this caveat).
- Key < 2048 bits → **low-medium** (1024-bit RSA is factorable with moderate resources).

### 4. DMARC

```bash
dig +short TXT _dmarc.{domain}
```

Evaluate:
- **Absent** → **medium-high** (no policy — receivers handle spoofed mail however they want).
- `p=none` → **medium** (policy exists but doesn't enforce — useful only for monitoring).
- `p=quarantine` → acceptable (spoofed mail goes to spam).
- `p=reject` → correct (spoofed mail is dropped).
- Check `sp=` (subdomain policy) — if absent, subdomains inherit `p=`, which may be weaker
  than intended.
- Check `rua=` / `ruf=` — absent means the domain owner gets no feedback on spoofing.
- `pct=` < 100 → note partial rollout (legitimate transition, but reduces protection).

### 5. CAA

```bash
dig +short CAA {domain}
```

Findings:
- **Absent** → **low-info** (any CA can issue certificates for the domain).
- Present → note which CAs are authorized; flag if `issuewild` is missing (wildcard
  certificates unconstrained).

### 6. MTA-STS

```bash
dig +short TXT _mta-sts.{domain}
# should return something like: v=STSv1; id=20240101
curl -sL https://mta-sts.{domain}/.well-known/mta-sts.txt
# should return: version, mode (enforce|testing|none), mx patterns, max_age
```

Findings:
- **Absent** (no TXT or no policy file) → **low** (SMTP TLS is opportunistic, susceptible
  to downgrade).
- `mode: testing` → **info** (monitoring only, no enforcement).
- `mode: enforce` → correct.

### 7. DANE / TLSA

```bash
# For each MX host:
dig +short TLSA _25._tcp.{mx_host}
```

Findings:
- **Absent** → **info** (DANE is uncommon; its absence is not a vuln, but its presence is
  a positive signal worth noting).
- Present → note and verify the record matches the MX certificate.

### 8. DNSSEC

```bash
dig +dnssec +short {domain} A
dig +short DS {domain}
# or check the full chain:
dig +sigchase +trusted-key=/etc/trusted-key.key {domain} A 2>&1 | tail -5
```

Findings:
- **No DNSSEC** → **info** (DNS responses can be spoofed, which undermines SPF/DKIM/DMARC
  lookups, but DNSSEC adoption is still partial — context-dependent severity).
- DNSSEC present but broken (SERVFAIL on `+dnssec`) → **medium** (worse than no DNSSEC —
  legitimate mail may fail validation).

## Severity summary

| Check | Absent / Misconfigured | Severity |
|---|---|---|
| DMARC p=none or absent | Spoofing unrestricted | medium-high |
| SPF +all or absent | Spoofing unrestricted (sender auth) | medium |
| DKIM not found (common selectors) | No message integrity | medium |
| MX without STARTTLS | Plaintext email transport | medium |
| DNSSEC broken (SERVFAIL) | Worse than absent | medium |
| SPF ~all without DMARC enforce | Softfail ignored by most receivers | low-medium |
| DKIM key < 2048 bits | Factoring feasible | low-medium |
| MTA-STS absent | TLS downgrade possible | low |
| CAA absent | Any CA can issue certs | low-info |
| DANE absent | No cert pinning for SMTP | info |
| DNSSEC absent | DNS spoofable (partial adoption) | info |

## Tooling

`dig` (or `drill`/`delv` for DNSSEC), `nslookup`, `openssl s_client` (STARTTLS check),
`curl` (MTA-STS policy fetch), `base64` + `openssl rsa` (DKIM key size). All standard
on Kali and macOS (install `bind` / `dnsutils` if `dig` missing).

## Validation gate

- [ ] MX records enumerated, STARTTLS tested on each.
- [ ] SPF record retrieved and mechanism evaluated (especially the `all` qualifier).
- [ ] DKIM probed with at least 10 common selectors; key size checked for any found.
- [ ] DMARC policy retrieved; `p=`, `sp=`, `rua/ruf`, `pct` evaluated.
- [ ] CAA record checked.
- [ ] MTA-STS TXT + policy file checked.
- [ ] DANE/TLSA records checked for MX hosts.
- [ ] DNSSEC validation attempted.
- [ ] Each finding tagged Demonstrated/Inferred per `finding-discipline`.

## Gotchas

- DKIM selector enumeration is inherently incomplete — failing to find a selector does NOT
  prove DKIM is absent. Tag as **Inferred** with the caveat that a non-standard selector
  may exist. Check email headers if you have a legitimate email from the domain (the
  `DKIM-Signature` header names the selector).
- SPF lookup count >10 causes a permanent error (permerror) that silently breaks SPF for
  all receivers — this is worse than `~all` because it's invisible to the domain owner.
- DMARC `p=none` with `rua=` is a legitimate monitoring configuration during rollout —
  report it but note the context (it's a finding, not necessarily negligence).
- Some domains legitimately don't send email (parked domains, API-only services). Check MX
  and SPF for `v=spf1 -all` (explicit "we don't send") before reporting missing email auth
  as a finding.
- MTA-STS requires HTTPS on `mta-sts.{domain}` — if that subdomain doesn't exist or has
  cert issues, the policy can't be fetched and MTA-STS is effectively absent.
- DANE requires DNSSEC on the MX domain (not the sender domain) — without DNSSEC, TLSA
  records are ignored by validating resolvers.
