---
name: quarry:verify
description: Promote a finding to Demonstrated via the 3-gate baseline/attack/diff protocol
argument-hint: "<finding_id> [engagement_dir]"
allowed-tools: Bash(*), Read(*)
---

# /quarry:verify — 3-gate finding confirmation

Usage: `/quarry:verify <finding_id> [engagement_dir]`

## What it does

Runs the 3-gate protocol (`engine/three_gate.py`) for a finding and persists
the verdict. This is the mechanical path from *Inferred* to *Demonstrated*:
no finding is promoted on the agent's say-so — it is promoted because a real
baseline/attack/diff showed a meaningful, non-noise difference.

- **Gate 1 — Baseline**: a benign request, recorded.
- **Gate 2 — Attack**: the exploit request, recorded.
- **Gate 3 — Diff**: baseline vs attack after stripping noise (timestamps,
  CSRF tokens, request IDs). A significant indicator (SQL error, stack trace,
  reflected `<script`, `/etc/`, …), a status change with body diff, or a large
  body diff = `confirmed`. No meaningful diff = `likely_fp`.

Every request goes through `ProtectedHTTPClient`, so it is validated against
the CURRENT engagement scope and consumes its single-use approval — same gate
as `/quarry:retest`.

## Flow

1. Build the verification spec from the finding's steps-to-reproduce: the
   benign baseline request and the attack request (method, URL, headers, body).
2. Run:
   ```bash
   python3 -m engine.three_gate --audit-dir <engagement_dir> --spec spec.json
   ```
   where `spec.json` is `{finding_id, baseline_url, attack_url,
   baseline_method?, attack_method?, baseline_headers?, attack_headers?,
   baseline_body?, attack_body?}`.
3. On `confirmed`: the finding's `evidence_tag` becomes `demonstrated`, its
   status advances DETECTED→CONFIRMED, and the baseline/attack round-trip is
   stored as `request_response` evidence (hashed, in the custody log).
4. On `inconclusive` / `likely_fp`: the finding is **never** promoted — the
   verdict is still recorded as evidence so the operator sees it was tested,
   and the finding stays for a human to judge.

Use `--no-record` to dry-run the gate and only print the verdict JSON.

## Rules

- `confirmed` is the ONLY verdict that promotes a finding. A tool "detecting"
  a vuln is a hypothesis until this gate (or another demonstration) passes.
- Destructive attack requests are not for this gate — it re-sends both
  requests; keep it to safe, idempotent probes (the same discipline as retest).
- The diff is on the response body snippet after noise stripping; if the real
  signal is in a header or out-of-band (OOB), confirm via the matching skill
  (`http-headers`, `oob-interactions`) and attach that evidence instead.

## Example

```
/quarry:verify F-1 engagements/acme-2026-09
```
