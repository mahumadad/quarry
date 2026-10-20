---
name: iot-ics
description: >
  IoT and ICS/SCADA attack methodology for authorized engagements:
  firmware extraction and analysis, UART/JTAG hardware access, MQTT and
  CoAP protocol abuse, Modbus and DNP3 enumeration. Keywords: IoT, ICS,
  SCADA, firmware, UART, JTAG, MQTT, CoAP, Modbus, DNP3, binwalk,
  embedded. ICS/OT protocols (Modbus, DNP3) are PASSIVE ENUMERATION ONLY
  — never send write/control-function commands to live ICS equipment
  without explicit, separately-documented operator sign-off, since a
  wrong write can cause physical/safety impact. Do NOT use for a generic
  Linux-based device's OS-level privesc once you have a shell (see
  linux-privesc), or for general network protocol abuse unrelated to
  OT (see network-infra).
metadata:
  type: platform
  phase: hunting
  tools: [binwalk, firmware-mod-kit, mqtt-pwn, modbus-cli, nmap-ics-scripts, jtagulator]
depends_on: [network-infra]
feeds_into: [chain-analysis, privesc-report]
chains_with: [linux-privesc, network-infra]
---

## Signals
- Physical device in scope with exposed debug headers, or firmware image (`.bin`, `.img`) provided.
- Network segment with MQTT (1883/8883), CoAP (5683/UDP), Modbus (502/TCP), or DNP3 (20000/TCP) traffic observed.
- Device labeled as OT/ICS/building-management/industrial in the scope document — treat this as a hard safety boundary, not just a technical one.

## Prerequisites
- Written authorization that EXPLICITLY covers physical hardware access and/or OT protocol testing — standard web/network scope does not imply OT scope.
- For ICS/SCADA specifically: written confirmation from the client's OT/safety team (not just the pentest sponsor) that passive-only testing is acceptable on the live segment, and ideally a non-production replica/digital twin for anything beyond passive enumeration.
- `binwalk`, `firmware-mod-kit`, a JTAGulator or Bus Pirate for hardware access, logic analyzer, UART-to-USB adapter.

## Methodology

### 1. Firmware extraction (from provided image or physical SPI/NAND dump)
```bash
binwalk -e firmware.bin
# Identify filesystem type and extract
binwalk -E firmware.bin    # entropy analysis to spot encrypted sections
file firmware.bin
# Look for hardcoded creds, keys, backdoor accounts in extracted rootfs
grep -r "password\|BEGIN RSA\|BEGIN PRIVATE" _firmware.bin.extracted/
```

### 2. UART access (serial console, often gives root shell with no auth)
```bash
# Identify pins with a multimeter/JTAGulator, then:
screen /dev/ttyUSB0 115200
# Common baud rates to try: 115200, 57600, 9600
# Interrupt bootloader (U-Boot) for a shell during boot
# (press a key during countdown, e.g. "Hit any key to stop autoboot")
```

### 3. JTAG access (for devices without an exposed UART)
```bash
# Use JTAGulator to identify pinout
# Then openocd with the identified target to dump flash / halt CPU
openocd -f interface/jlink.cfg -f target/<chip>.cfg
```

### 4. MQTT enumeration (passive-first, then limited active probing with permission)
```bash
# Passive: sniff existing traffic
mosquitto_sub -h target-broker -t '#' -v
# Active enumeration (confirm anonymous access / weak ACLs)
mosquitto_sub -h target-broker -p 1883 -t '#' -v -u '' -P ''
mqtt-pwn    # interactive framework for broker enum + topic fuzzing
```

### 5. CoAP enumeration
```bash
coap-client -m get coap://target-device/.well-known/core
# Resource discovery reveals exposed endpoints similar to a REST API
```

### 6. Modbus — PASSIVE READ-ONLY ENUMERATION
```bash
nmap -p 502 --script modbus-discover target-plc-ip
# Read-only function codes ONLY (0x01-0x04): read coils/registers, never write (0x05/0x06/0x0F/0x10)
modbus-cli --host target-plc-ip --port 502 read-holding-registers --address 0 --count 10
```

### 7. DNP3 — PASSIVE READ-ONLY ENUMERATION
```bash
nmap -p 20000 --script dnp3-info target-rtu-ip
# Use a passive protocol analyzer (Wireshark with the DNP3 dissector) on a network tap/span port
# rather than active probing against a live RTU/master
```

## Tooling
`binwalk`, `firmware-mod-kit`, `Firmware Analysis Toolkit (FAT)` with QEMU for emulation, `JTAGulator`, `openocd`, `mosquitto` clients, `mqtt-pwn`, `coap-client`, `nmap` NSE ICS scripts, Wireshark (ICS dissectors).

## Validation Gate
- Firmware backdoor/credential findings must be confirmed against a live device or an emulated instance (QEMU via Firmware Analysis Toolkit), not just "string found in extracted filesystem."
- Any ICS/OT finding reported as exploitable must still be labeled per the engagement's write-restriction: Demonstrated only for read-only confirmation; write/control-plane impact stays **Unproven**/theoretical unless the operator explicitly authorized active testing on a non-production replica.
- Log every Modbus/DNP3 request's function code explicitly in evidence to prove no write function codes were used.

## Gotchas
- **This is the one skill in the plugin where "just try it" is not acceptable even with general scope sign-off.** A write to a Modbus coil or DNP3 point on live equipment can have physical consequences (valve, breaker, pump) — this requires the explicit human gate called out above, every time, independent of the general engagement authorization.
- Firmware update servers often check for valid signatures — a repacked/modified firmware may simply be rejected rather than flashed, which is a safe way to test input validation without bricking a device.
- UART/JTAG access is destructive to warranty and can brick hardware — only use devices explicitly provisioned as test/throwaway units.
- Many "IoT" devices are just embedded Linux — once you have a shell via UART, pivot to linux-privesc for further escalation on the device itself.
