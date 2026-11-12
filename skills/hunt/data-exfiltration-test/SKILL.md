---
name: data-exfiltration-test
description: >-
  Test whether DLP and monitoring controls detect data exfiltration using MITRE ATT&CK TA0010 techniques.
---

# Data Exfiltration Control Testing

> MITRE ATT&CK: TA0010 (Exfiltration)
> Gate: EVERY exfiltration test requires explicit operator authorization
> Purpose: Test whether DLP and monitoring controls detect data leaving

## Objective

Assess the effectiveness of data loss prevention (DLP) controls and
monitoring by attempting controlled exfiltration of test data through
various channels.

## Pre-checks

1. Scope MUST explicitly authorize exfiltration testing
2. Use ONLY synthetic test data — NEVER real sensitive data
3. Confirm monitoring/SOC team is aware (or not, depending on test type)
4. Prepare test data tokens that can be traced back to the test
5. Operator gate: approve each exfiltration channel before testing

## Steps

### 1. DNS Exfiltration Test

- Encode test data in subdomain labels (e.g., base32-encoded chunks)
- Use OAST integration (engine/oast.py) for callback collection
- Test: can data leave via DNS queries without detection?
- Channels: direct DNS, DNS-over-HTTPS, DNS tunneling
- Evidence: callback received = exfiltration possible, not detected

### 2. HTTP(S) Exfiltration Test

- Test data in HTTP headers (custom headers, cookies, user-agent)
- Test data in request body (POST to external endpoint)
- Test data in URL parameters
- Test data encoded in image/file uploads
- Use OAST endpoint as receiver
- Evidence: request received at OAST = exfiltration channel open

### 3. Out-of-Band Channel Testing

- ICMP tunneling feasibility (ping with data payload)
- WebSocket exfiltration (if WebSocket connections allowed outbound)
- SMTP exfiltration (email with test data if mail relay available)
- Evidence: successful OOB data receipt

### 4. Encoding and Evasion

- Base64/hex encoding of test data
- Chunked transfer in small increments
- Steganographic embedding in allowed file types
- Compression before exfiltration
- Purpose: test if DLP inspects encoded/compressed content

### 5. Volume and Rate Assessment

- Determine maximum data transfer rate before detection
- Test sustained low-volume exfiltration (slow drip)
- Test burst exfiltration (large volume, short window)
- Evidence: threshold at which monitoring triggers (if ever)

## Gotchas

- ALWAYS use synthetic test data, NEVER real PII/secrets
- Some DLP solutions only inspect cleartext — encrypted channels may bypass
- Cloud environments may have different egress controls than on-prem
- WAF/proxy may block some channels but not log the attempt
- DNS exfil is often the last channel blocked — test it

## Chain Anchors

- gives: exfiltration-path, dlp-bypass
- needs: rce, shell, ssrf, or any outbound communication capability

## Evidence Requirements

- Each test: channel used, data sent (hash only), received confirmation
- Detection assessment: was it logged? was it blocked? was it alerted?
- Timeline: how long between exfiltration and detection (if detected)
- Tag: Demonstrated (data exfiltrated undetected) / Inferred (channel open)
- Include OAST correlation tokens for each test
