---
name: quarry:run
description: Create or continue a deterministic, auditable workflow run
argument-hint: "[workflow] [--resume <run_id>]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:run [workflow] [--resume <run_id>]

Uses `engine/orchestrator.py` as the sole execution entry point. The default
workflow is `workflows/full-pentest.yaml`; do not execute phases from memory
or build a second sequence from `router.py`.

1. Verify engagement, scope, authorization, and active time window.
2. Run the `ToolRegistry` preflight: persist capabilities without backend and chosen versions;
   select lists via `WordlistIndex` when the task uses them. Do not install tools
   or download lists implicitly.
3. Without `--resume`: create the run with the chosen workflow and the discovered
   coverage cells. Save and display its `run_id`.
4. With `--resume`: load that run, recover `running` tasks as
   `interrupted`, review their artifacts, and continue only from the first
   pending or interrupted task.
5. Before each task, load `Orchestrator.briefing()`. Execute the indicated skill,
   persist raw artifacts first, then return one of these states:
   `completed`, `skipped`, `failed`, or `blocked`, with a reason.
6. A human gate blocks the run. Resume only after operator approval
   via `approve_gate`; never approve on behalf of the operator.
7. Do not convert timeout, truncated output, missing tool, or exception into
   `tested_clean`. Those cases are `failed`, `blocked`, `tool_unavailable`, or `inconclusive`.
8. Before validating/reporting, apply self/program duplicate convergence and link IDs or
   references; do not re-run the pipeline for a re-detection of the same root cause.
9. On completion, display states, gaps, artifacts, and custody. The run only
   truly ends after QC, delivery, and closeout.

All network actions must use `ProtectedHTTPClient` or `ToolRunner`; do not create
parallel requests that bypass the common policy.
