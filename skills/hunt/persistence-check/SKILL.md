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

## Commands

```bash
# Scheduled tasks / cron
crontab -l 2>/dev/null; ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null
systemctl list-timers --all 2>/dev/null
# Windows: schtasks /query /fo LIST /v  ;  Get-ScheduledTask

# Service / startup persistence
systemctl list-unit-files --state=enabled 2>/dev/null
ls -la /etc/init.d /etc/rc*.d ~/.config/autostart 2>/dev/null
# Windows: Get-CimInstance Win32_Service | ? {$_.StartMode -eq 'Auto'}
#          reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Account persistence
awk -F: '$3>=1000{print}' /etc/passwd; grep -v '^#' /etc/sudoers.d/* 2>/dev/null
ls -la ~/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null

# Web shell indicators (callback eval/exec in web roots)
grep -rEl "eval\(|base64_decode\(|assert\(|system\(" /var/www 2>/dev/null
```

Post-exploitation step: requires the standing exploitation gate and a host you
are authorized to inspect.

## Validation Gate (minimum proof)

- **Demonstrated:** a specific persistence artifact identified with its exact
  location and content (the cron line, the service unit, the authorized_keys
  entry, the web-shell file hash), plus how it would re-grant access.
- **Inferred:** an anomaly consistent with persistence but not confirmed as
  attacker-controlled (could be legitimate admin tooling — say so).
- Attribution matters: do not label legitimate automation as malicious
  persistence without evidence it is attacker-placed.

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
