---
name: lateral-movement
description: >-
  Assess lateral movement paths between compromised and adjacent assets using MITRE ATT&CK TA0008 techniques.
---

# Lateral Movement Assessment

> MITRE ATT&CK: TA0008 (Lateral Movement)
> Prerequisites: Confirmed RCE, shell, or authenticated access on at least one asset
> Gate: Scope MUST explicitly include internal pivoting/lateral movement

## Objective

Assess whether a compromised host can be used to reach additional
internal assets, services, or network segments.

## Pre-checks

1. Confirm scope includes lateral movement testing
2. Verify initial access is confirmed (not hypothetical)
3. Document the pivot point (host, access level, method)
4. Confirm network segmentation boundaries with operator

## Steps

### 1. Internal Network Discovery

- Map internal network from compromised host (arp -a, ip neigh, /etc/hosts)
- Identify reachable subnets (ping sweep or port scan internal ranges)
- Document: which internal hosts respond, which ports are open
- Evidence: network map with reachable hosts

### 2. Service Account Enumeration

- Identify service accounts and their privileges
- Check for credential reuse across services
- Look for hardcoded credentials in config files, environment variables
- Evidence: list of discovered service accounts and their access level

### 3. Credential Reuse Testing

- Test discovered credentials against other internal services
- Check for password patterns (same password, predictable variations)
- Test default credentials on internal services
- Gate: each credential test against a new host requires operator confirmation

### 4. Trust Relationship Mapping

- Identify trust relationships between services (shared DBs, internal APIs)
- Check for mutual TLS, API keys, shared secrets
- Map service-to-service authentication
- Evidence: trust relationship diagram

### 5. Pivot Feasibility Assessment

- Test SSH tunneling / port forwarding capability
- Assess SOCKS proxy feasibility for deeper pivoting
- Check for jump boxes or bastion hosts
- Document: what additional access each pivot provides

## Gotchas

- Internal services may have different WAF/IDS rules than external
- Credential spraying internally can trigger lockouts faster
- Some services trust internal IPs implicitly — that's a finding
- Time-based checks: internal services may have different timeouts

## Chain Anchors

- gives: internal-network-access, credential-reuse, pivot-internal
- needs: rce, authenticated-access, shell

## Evidence Requirements

- Each lateral movement attempt: source host, target host, method, result
- Network diagrams showing reachable segments
- All credential tests logged with timestamps
- Tag: Demonstrated (successful pivot) / Inferred (reachable but untested)
