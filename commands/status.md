---
name: quarry:status
description: Engagement dashboard — phase, findings, coverage, budget, gaps, next steps
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:status

Reads all persisted state from the active engagement and presents it as
a single-screen dashboard. Modifies nothing — this is a read-only
command. Useful when resuming a session, after a context compaction, or
simply to get oriented.

## Precondition

- `.pentest-state/engagement.json` must exist. If it does not, say so
  clearly and recommend `/quarry:engage <target>` — do not fabricate an
  empty state that looks like a dashboard.

## Exact steps

1. Load `EngagementState` → current phase, target, creation date,
   phase transition history.
2. Load `Scope` → count of in-scope/out-of-scope entries (not the full
   detail — that is `/quarry:scope --show`'s job).
3. Load `FindingsStore.summary()` → total, breakdown by status
   (detected/confirmed/exploited/chained/validated/reported/killed) and
   by severity.
4. Load `ChainEngine.list_chains()` → total count and by status
   (candidate/verified/killed).
5. Load `CoverageTracker.summary()` → covered assets, total
   vuln_classes, coverage ratio, cells with finding, skipped cells.
6. Load `BudgetManager.summary()` → usage per phase
   (used/limit/remaining), highlight any phase at ≥80% usage.
7. Load `RebuttalEngine.summary()` if sessions exist → count by outcome
   (pending/accepted/stall/killed/exhausted). Highlight `pending`
   sessions — these are unfinished validation work.
8. Compute coverage gaps (`CoverageTracker.get_gaps()`) and show the
   top 10 most relevant (prioritize assets with findings already
   detected in other classes — more findings are likelier there).
9. Derive the recommended next action(s) based on phase and state
   (table below).

## "Recommended next action" logic

| Observed situation | Recommendation |
|---|---|
| Phase `INIT` or no engagement | `/quarry:engage <target>` |
| Phase `SCOPED`, no recon | `/quarry:recon` |
| Phase `RECON`, no maps | `/quarry:map` |
| Phase `MAPPED`/`HUNTING`, coverage <100% and hunting budget <80% | `/quarry:hunt` on the listed gaps |
| ≥2 findings `CONFIRMED`/`EXPLOITED` without chain analysis | `/quarry:chain` |
| Accumulated `DETECTED`/`CONFIRMED` findings without pipeline pass | `/quarry:validate` |
| `VALIDATED` findings not yet reported | `/quarry:report` |
| Any phase budget ≥80% | Escalate to operator before continuing — do not recommend more tool calls in that phase without a human decision |
| Rebuttal sessions in `pending` | Complete those sessions before opening new work |

If multiple rows apply simultaneously, list them all in urgency order
(critical budget and pending rebuttals first, then phase advancement).

## Edge cases

- **Partially corrupt or missing state files** (e.g.
  `findings.json` does not exist but `engagement.json` does — freshly
  created engagement): treat as "0 findings", not as an error, unless
  the JSON exists and is malformed — in that case, report it as a state
  problem to investigate, do not silently ignore it.
- **Phase and content inconsistent** (e.g. phase `REPORTING` but 0
  `VALIDATED` findings): flag the inconsistency explicitly in the
  dashboard, do not just show the numbers separately.
- **Very old engagement without recent activity** (distant
  `updated_at`): mention it — it may be relevant for deciding whether
  the scope/authorization is still valid before resuming.

## Expected output

Single-screen dashboard, in this order:
1. Target, engagement ID, current phase, last activity.
2. Scope: in/out-of-scope count, authorization reference present yes/no.
3. Findings: total and breakdown by status and severity.
4. Chains: total and by status.
5. Coverage: ratio, assets, cells with finding, top gaps.
6. Budget: usage per phase, ≥80% alerts.
7. Rebuttal: pending sessions if any.
8. Current run: `run_id`, task states, gates, interrupted tasks, and next
   action from `Orchestrator.resume_plan()`.
9. Integrity: `Orchestrator.doctor()` result for artifacts and custody.
10. Recommended next actions (prioritized list, from the table above).
