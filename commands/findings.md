---
name: quarry:findings
description: List findings filtered by status, class, and optionally their chain analysis
argument-hint: "[--status <status>] [--class <class>] [--chains]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:findings [--status <status>] [--class <class>] [--chains]

Lists findings from the active engagement, with combinable filters.
Read-only command — does not modify `findings.json` or `chains.json`.

## Precondition

- `.pentest-state/findings.json` must exist. If it does not exist or is
  empty, say so ("0 findings registered") and suggest `/quarry:hunt` —
  this is not an error, it may simply be the early engagement state.

## Arguments

- `--status <status>` — one of `detected`, `confirmed`, `exploited`,
  `chained`, `validated`, `reported`, `killed` (`FindingStatus` values).
  If the value does not match any, list the valid ones and ask to repeat.
- `--class <class>` — one of the `ALL_VULN_CLASSES` from
  `engine/coverage.py`, or a skill name `*` (normalize before comparing).
  If no match, list close matches (partial match) before failing.
- `--chains` — in addition to the list, for each displayed finding,
  resolve and show its `chain_refs` and any `Chain` from `chains.json`
  where its ID appears in `findings[]`.
- No arguments: list all, unfiltered, ordered by severity
  (critical → info) and within each severity by status (most advanced
  first: reported → validated → ... → detected → killed last).

## Exact steps

1. Load the full `FindingsStore`.
2. Apply filters in order: `--status` first (use
   `FindingsStore.list_by_status`), then `--class` on that subset (use
   `FindingsStore.list_by_class`, or filter manually if both filters
   are combined).
3. If `--chains`: load `ChainEngine`, and for each filtered finding,
   `chain.get_chain(ref)` for each ID in `finding.chain_refs`, plus a
   direct search in `list_chains()` in case the finding appears in a
   chain without `chain_refs` having been updated yet (do not assume
   `chain_refs` is always in sync — keeping it current is the
   responsibility of `/quarry:chain` and `/quarry:validate`, but verify
   here anyway).
4. Render table.

## Table format (without `--chains`)

| ID | Title | Severity | Status | Evidence tag | Asset |
|---|---|---|---|---|---|

## Format with `--chains`

Same as above, plus for each finding with associated chains, an
indented sub-list:
```
F-A1B2C3D4  IDOR on /api/orders/:id  high  confirmed  inferred  api.target.com
  └─ C-9F8E7D6C: idor + rate-limiting → mass-data-exfiltration (critical, candidate)
```

## Edge cases

- **Combined filter with no results** (e.g. `--status killed --class
  ssrf` and there are none): state it explicitly ("0 findings matching
  those filters"), do not show an empty table without context — and
  suggest running without `--class` to see if the status exists in
  other classes.
- **Finding with `chain_refs` pointing to an ID that no longer exists
  in `chains.json`** (e.g. a chain was merged/pruned in
  `/quarry:validate`): flag it as a broken reference instead of silently
  omitting it — it is a signal that state cleanup is needed.
- **Many findings (>30)**: paginate or group by severity with counts,
  and ask whether full detail or just an aggregate summary is wanted —
  do not dump a giant table without being asked.
- **`--class` matching a skill that covers multiple vuln_classes**
  (e.g. `--class xss` should include `xss-reflected`, `xss-dom`, and
  `xss-stored`): expand the filter to all 3, not just an exact string
  match.

## Expected output

- Filtered table with the total count at the top ("14 findings, filtered
  to 5").
- If `--chains`: chain sub-lists per finding, as shown above.
- A 1-line summary at the end: how many of those listed are in each
  status, for quick context without having to count rows.
