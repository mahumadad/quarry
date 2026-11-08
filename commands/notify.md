---
name: quarry:notify
description: Immediately escalate a critical finding to stakeholders
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:notify — Immediate critical finding escalation

Usage: `/quarry:notify <finding_id>`

## When it is MANDATORY

- Critical finding confirmed in PRODUCTION (RCE, mass data access,
  admin account takeover) — notify the same day, not in the report.
- Evidence of PRIOR target compromise (foreign webshell, client
  credentials in leaks, another actor's activity) — the client may have
  an active incident; your engagement takes a back seat.
- Out-of-scope action executed by mistake — immediate transparency.
- Finding with physical safety or legal risk (minors' data, critical
  infrastructure).

## Protocol

1. **Freeze the attack line**: do not continue exploiting the critical
   finding until the client confirms receipt — an RCE in prod is still
   prod.
2. Complete `templates/critical-alert.md`: verdict, minimum evidence
   sufficient to act, what NOT to touch, suggested immediate mitigation.
3. Send through the emergency channel defined in `/quarry:engage`
   (emergency_contact). Encrypt if the channel is untrusted
   (`/quarry:deliver` with gpg applies for attachments).
4. Record the send in custody (actor: operator, event: critical_alert).
5. Resume the engagement only after client ack (or a documented operator
   decision if the client does not respond within the agreed timeframe).

## Rules

- The alert contains the minimum needed to act — full detail goes in the
  report. Sensitive evidence (actual extracted data) does NOT go in the
  alert.
- If the emergency channel fails, escalate through the secondary contact
  and record both attempts in custody.
- Never publish/share the finding outside the agreed channel — including
  "anonymous vendor notice" — without client authorization.
