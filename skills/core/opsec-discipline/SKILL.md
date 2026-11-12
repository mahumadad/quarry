---
name: opsec-discipline
description: >
  Operational security rules for running scans and tools against a live target without
  causing outages, tripping unnecessary alerting, or leaking engagement details. Covers
  rate limiting, user-agent/identity hygiene, timing, and responsible handling of any
  sensitive data recon turns up. Use before configuring any scanning tool, and whenever
  a tool's default settings would be noisy or aggressive. Not about anonymizing identity
  from the client — the client knows this is a sanctioned test; this is about not breaking
  things and not spraying findings outside the engagement's secure channels.
metadata:
  type: core
  phase: scoped
  tools: [nmap, masscan, ffuf, gobuster, tor, proxychains]
depends_on: [scope-discipline]
feeds_into: [active-recon, port-scan, service-enumeration, web-crawling]
---

## Signals

- Before running any tool whose default concurrency/rate could degrade a production service.
- Before running tools against infrastructure described as fragile, low-capacity, or
  production-only (no staging equivalent) in the RoE.
- When a tool's output or a report draft needs to be stored or transmitted.
- When legally-adjacent findings (PII, credentials, leaked secrets) are discovered.

## Prerequisites

- RoE testing window and rate-limit/IP-allowlist requirements from `scope-discipline`.
- Know whether the client wants detection (to test their blue team) or wants to avoid
  tripping alerts (to avoid noise/false incidents) — this changes the whole approach and
  must be stated explicitly in the RoE, not assumed.

## Methodology

### Rate limiting
1. Default to conservative timing on anything against production:
   ```bash
   nmap -sS -T2 --max-rate 50 -p- 10.0.0.0/24          # polite timing, capped pps
   masscan 10.0.0.0/24 -p1-65535 --rate 500             # explicit low rate, not --rate 100000
   ffuf -u https://target/FUZZ -w wordlist.txt -rate 20 -p 0.1-0.5   # jittered delay between requests
   gobuster dir -u https://target -w wordlist.txt -t 10 --delay 200ms
   ```
2. Scale up only after confirming with the client that the target can absorb it, or when
   testing a dedicated staging environment.
3. Watch for self-inflicted lockouts: aggressive auth brute-forcing can trigger account
   lockout policies or WAF IP bans that end the engagement early.
   ```bash
   # check ban status before continuing a sequence
   curl -s -o /dev/null -w "%{http_code}\n" https://target/
   ```

### Identity / user-agent hygiene
4. Set an identifiable, non-default user agent when the RoE calls for traceable testing
   (so the client's logs can distinguish engagement traffic from real attacks):
   ```bash
   curl -A "PentestEngagement-<ClientCode>-<YourHandle>" https://target/
   ffuf -u https://target/FUZZ -w wordlist.txt -H "User-Agent: PentestEngagement-ACME-2026"
   ```
5. Only rotate/anonymize user-agents or source IPs (proxychains, Tor, rotating proxy pools)
   when the engagement is explicitly a red-team/detection-evasion test with sign-off for
   that specific technique. Default assumption is attributable traffic, not evasion —
   evasion techniques require their own line item in the RoE.
   ```bash
   # only under an explicit detection-evasion mandate:
   proxychains4 nmap -sT -Pn target
   ```

### Timing and scheduling
6. Respect the agreed testing window (e.g. business hours only, or off-hours only for
   availability-sensitive targets). Schedule long scans accordingly:
   ```bash
   at 22:00 <<< "nmap -sS -p- -T3 -oA fullscan target"
   ```

### Anonymous lab (Docker+Tor+VPN)
6. Cuando el engagement requiere anonimato (red team evasivo, bug bounty sin
   exponer IP, targets que bloquean rangos conocidos):
   ```bash
   # Levantar el lab anónimo (Mullvad debe estar conectado primero)
   cd ~/Dev/personal/pentest-vm/docker && ./anonlab.sh up

   # Verificar la cadena: debe mostrar IP de exit Tor, IsTor: true
   ./anonlab.sh status

   # Shell interactivo en kali (todo el tráfico va por Tor)
   ./anonlab.sh shell

   # Configurar el engagement para usar el backend anonlab
   # en .pentest-state/toolrunner.json: {"backend": "anonlab"}
   ```
7. Dentro del lab, las herramientas rutean automáticamente por Tor vía env
   vars (`ALL_PROXY`, `HTTP_PROXY`). Para herramientas que no respetan env
   vars, usar los wrappers:
   ```bash
   tscan target.com              # nmap connect-scan vía Tor (resuelve DNS por Tor)
   ptor <tool> [args]            # proxychains4 wrapper para cualquier tool TCP
   web whatweb <url>             # whatweb/nikto con UA de Windows, vía Tor
   ```
8. La cadena de red es fail-closed: el contenedor kali no puede hacer
   conexiones directas a internet — solo a través de Tor. Si Tor cae,
   las conexiones fallan (no hay fallback a clearnet).
9. No usar el lab anónimo para engagements donde el cliente espera tráfico
   atribuible — si el RoE pide UA identificable o IP whitelisteda, usar
   backend `local` o `kali`.

### Data handling
7. Store all engagement artifacts (scan output, screenshots, credentials found) only in the
   client's designated secure channel/repo — never in a personal/unencrypted location, never
   pasted into a public paste service or ticket, never committed to a public git repo.
8. Any live credentials, API keys, or PII discovered during recon must be flagged immediately
   per the RoE's data-handling clause (usually: do not exfiltrate beyond proof, redact in
   reports, immediate notification for anything indicating ongoing compromise by a third party).
9. If recon surfaces evidence of a real, active compromise by someone else (not the test team),
   stop and escalate immediately — this is outside the engagement and needs client incident
   response, not more scanning.

## Tooling

`nmap` (`-T0`..`-T5`, `--max-rate`, `--scan-delay`), `masscan --rate`, `ffuf -rate -p`,
`gobuster --delay`, `curl -A`, `proxychains4`, `tor`, `at`/`cron` for scheduling.

## Validation gate

- [ ] Rate/concurrency settings match what the RoE allows for this target class.
- [ ] User-agent/traffic attribution matches the RoE's stated detection posture
      (attributable vs. evasion-testing).
- [ ] Testing window matches the RoE schedule.
- [ ] No engagement data stored or transmitted outside the client's designated channel.
- [ ] If anonlab backend: Tor circuit verified (`anonlab status`), Mullvad connected,
      fail-closed confirmado (curl directo falla).

## Gotchas

- Tool defaults are almost never safe for production: masscan's default rate and nmap's `-T5`
  can saturate a link or trip IDS/IPS auto-blocking within seconds.
- "Stealthy" scanning (`-sS`, fragmented packets, decoys) is not the same as "polite" scanning
  (rate-limited) — pick based on what the RoE actually asked for, don't default to stealth
  just because it feels more professional.
- A WAF ban or account lockout triggered by your own brute-force can masquerade as a finding
  ("no rate limiting!") when actually it means the opposite — verify before reporting.
- Findings discussed in Slack/email outside the agreed secure channel create a data-handling
  violation even if the finding itself is accurate.
