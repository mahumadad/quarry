---
name: quarry:resume
description: Resume an engagement without repeating or losing tasks after an interruption
argument-hint: "[run_id]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:resume [run_id]

1. Load `.pentest-state/engagement.json`, scope, authorization, and time window.
   If any is missing, corrupt, or expired, halt fail-closed.
2. Run `Orchestrator.doctor()` and display integrity issues before
   continuing. A broken chain or altered evidence requires human review.
3. Select the indicated run or the most recent one. Run
   `recover_interrupted(run_id)`: every task that was `running` becomes
   `interrupted`, never completed.
4. Present `resume_plan`: phase, next task, attempts, recent failures,
   available artifacts, and pending gates.
5. Resume with `/quarry:run --resume <run_id>` only after verifying the
   artifacts of interrupted tasks. If their result was persisted and is
   intact, record it; if not, re-run that task idempotently.
6. Do not skip tasks just because their skill appears in an old checkpoint:
   `runs.json` and `journal.jsonl` are the authoritative source.
