---
name: quarry:scope
description: Show or modify the active engagement scope — add/remove rules, view current state
argument-hint: "[--add|--remove|--show]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:scope [--add|--remove|--show]

The only command (along with `/quarry:engage`) that can modify
`.pentest-state/scope.json`. Any scope change takes effect immediately
on the `hooks/hooks.json` guard on the next Bash call — no session
restart required.

Without an argument: equivalent to `--show`.

## Precondition

- An active engagement with scope already initialized by
  `/quarry:engage` must exist. If `.pentest-state/scope.json` does not
  exist, point out that `/quarry:engage` is missing — this command does
  not create an engagement from scratch.

## `--show` (default)

1. Load `Scope.load(Path("<audit_dir>/.pentest-state/scope.json"))`.
2. Display as table: in-scope (pattern, type, notes), out-of-scope
   (pattern, type, notes), engagement rules, authorization reference.
3. If there are discovered assets in `coverage.json` that do not match
   any in-scope or out-of-scope entry (gray zone — e.g. a new
   subdomain under a non-explicit wildcard), list them separately as
   "unclassified, requires operator decision".

## `--add`

1. Ask: in-scope or out-of-scope?, pattern (domain/IP/CIDR/wildcard/
   URL), type, optional notes.
2. Validate the pattern syntactically before saving (valid IP, parseable
   CIDR, well-formed domain) — use the same logic from
   `Scope._matches`/`_ip_in_cidr` to pre-check, not just save free
   text.
3. If adding to **in-scope**: explicitly confirm with the operator that
   this is covered by the existing authorization, or that there is a
   new authorization for this expansion — do not assume that "add"
   automatically means authorized. Ask for a reference if it is a real
   scope expansion, not just a finer detail of the already authorized
   scope.
4. Save with `Scope.add_in_scope(...)` / `add_out_of_scope(...)` and
   `Scope.save(...)`.
5. If the pattern added to out-of-scope matches something already
   tested in `coverage.json` or an existing finding in `findings.json`:
   warn the operator — they may need to decide what happens with that
   work already done (discard from the report? keep because it was done
   before the exclusion?).

## `--remove`

1. Ask for the exact pattern to remove (from in-scope or out-of-scope
   — ask which if not obvious).
2. Show the full entry before deleting and confirm.
3. If removing an **in-scope** entry that has associated findings
   (`target_asset` matches the pattern in `findings.json`): stop and
   warn explicitly — removing scope must not silently delete or
   invalidate already-registered findings. Ask whether they really want
   to remove it (leaves those findings "orphaned" from active scope,
   but the historical report keeps them) or if the intent is something
   else (e.g. pause new testing there without withdrawing formal scope).
4. Save changes.

## Edge cases

- **Removing the only in-scope entry** (leaves scope empty): warn that
  this blocks any future offensive action (plugin `CLAUDE.md` rule:
  no scope, no actions) and confirm it is intentional (e.g. engagement
  paused).
- **Duplicate or overlapping pattern with an existing one** (e.g.
  adding `*.target.example.com` when `app.target.example.com` already
  exists): flag it, do not block — it may be intentional (expanding
  from one subdomain to the full wildcard), but the operator must
  confirm consciously.
- **In-scope vs out-of-scope conflict** (the same pattern, or one that
  covers the other, in both lists): `Scope.is_in_scope` already
  resolves this by giving priority to out-of-scope, but flag it anyway
  as confusing configuration worth cleaning up.
- **`--add`/`--remove` without specifying type or pattern**: ask, do
  not infer from conversation context unless unambiguous.

## Expected output

- Resulting scope table after any change (always show the final state,
  not just "done").
- If there were warnings (orphaned findings, empty scope, overlap),
  list them explicitly before confirming that the change was saved.
