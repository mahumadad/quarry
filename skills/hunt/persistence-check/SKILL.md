---
name: persistence-check
description: >-
  Detect pre-existing persistence mechanisms on compromised assets using MITRE ATT&CK TA0003 techniques.
---

# Persistence Mechanism Detection

> MITRE ATT&CK: TA0003 (Persistence)
> Purpose: Detect pre-existing persistence mechanisms — NOT plant them
> Gate: Read-only assessment unless operator authorizes deeper inspection

## Objective

Check whether the target system shows signs of pre-existing backdoors,
unauthorized persistence mechanisms, or indicators of prior compromise.
This is a DEFENSIVE check, not an offensive implant exercise.

## Pre-checks

1. Confirm scope includes persistence checks
2. Clarify: this skill DETECTS persistence, it does not CREATE it
3. Document baseline access level and inspection boundaries
4. Get operator approval for any file system inspection beyond web root

## Steps

### 1. Web Shell Detection

- Scan web-accessible directories for common webshell patterns
- Check for recently modified PHP/JSP/ASPX files outside normal deploy cycle
- Look for obfuscated code patterns (base64_decode, eval, gzinflate chains)
- Check file permissions anomalies (world-writable in web root)
- Evidence: list of suspicious files with timestamps and content hashes

### 2. Scheduled Task / Cron Review

- List crontabs for all users (crontab -l per user)
- Check /etc/cron.d/, /etc/cron.daily/ for unexpected entries
- Review systemd timers (systemctl list-timers)
- Check Windows Task Scheduler if applicable
- Evidence: any unexpected scheduled tasks with their commands

### 3. Service and Startup Review

- List enabled systemd services, compare against expected baseline
- Check /etc/rc.local, init.d scripts for modifications
- Review .bashrc/.profile for suspicious additions
- Check for unexpected SUID/SGID binaries
- Evidence: unexpected services or startup modifications

### 4. Account Persistence Check

- Check for recently created user accounts
- Look for unauthorized SSH keys in ~/.ssh/authorized_keys
- Review /etc/passwd and /etc/shadow for anomalies
- Check for accounts with UID 0 besides root
- Evidence: unauthorized accounts or SSH keys

### 5. Network Persistence Indicators

- Check for unexpected listening ports (ss -tlnp, netstat -tlnp)
- Look for reverse shell indicators in process list
- Check iptables/nftables for unusual NAT or forwarding rules
- Review DNS configuration for unauthorized resolvers
- Evidence: unexpected network listeners or configurations

## Gotchas

- This is DETECTION, not IMPLANTATION — never create persistence
- False positives: legitimate admin tools (ansible, puppet agents)
- Some monitoring agents look like persistence (check with operator)
- Container environments have different persistence patterns
- Cloud instances may have legitimate metadata service access

## Chain Anchors

- gives: compromise-indicators, persistence-detected
- needs: shell, rce, authenticated-access

## Evidence Requirements

- Each suspicious finding: file path, timestamp, content hash, why suspicious
- Comparison with expected baseline (if available)
- Tag: Demonstrated (confirmed backdoor) / Inferred (suspicious indicators)
- CRITICAL: if active compromise is detected, escalate to operator IMMEDIATELY
