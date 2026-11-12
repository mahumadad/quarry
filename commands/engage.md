---
name: quarry:engage
description: Start a new pentest engagement — scope, audit directory, target card
argument-hint: "<target>"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:engage <target>

Initializes a new engagement. It is the only command that can create an
engagement from scratch; all other commands require this one to have run
first with confirmed scope.

## Argument

`<target>` — main target name or domain (e.g. `target.example.com`,
`acme-corp.test`). Required. If missing, ask before continuing.

## Edge cases first

- If an active engagement already exists (there is a
  `.pentest-state/engagement.json` in the resolved audit directory for
  this target) and its phase is not `closed`: show the current state
  (phase, scope, findings) and ask whether to resume that engagement or
  create a new one with a date suffix. Do not overwrite silently.
- If the operator cannot provide a verifiable authorization reference
  (email, letter, contract, bug bounty program with published scope):
  **stop the command**. No authorization, no engagement. This is
  non-negotiable — it is rule #1 of the plugin's `CLAUDE.md`.
- If the target matches a domain/IP already marked out-of-scope in a
  previous engagement by the same operator (if a sibling audit dir is
  found), warn before continuing.

## Exact steps

1. **Resolve audit directory.** Default convention:
   `$QUARRY_AUDIT_DIR/<slug>_audit/` (if `$QUARRY_AUDIT_DIR` is not
   set, ask the operator). `<slug>` is the target in lowercase, without
   protocol, with `.` and non-alphanumeric characters replaced by `-`
   (e.g. `app.target.example.com` → `target-example-com_audit`, but
   prefer the short brand name if the operator provides it, e.g.
   `acme-corp_audit`). Ask the operator whether they want that path or
   another before creating anything.

2. **Ask for and confirm scope — explicitly, before touching the target:**
   - Domains/IPs/CIDRs **in-scope** (one or more).
   - Domains/IPs/paths **out-of-scope** (if none, ask "is everything
     resolving under this target in scope, or are there exclusions?" —
     do not assume "no exclusions" by omission).
   - **Authorization reference**: who authorized, how (email/letter/
     program), date. Store the text or link verbatim, not summarized.
   - **Engagement rules**: allowed hours, rate limits, prohibited
     techniques (e.g. "no DoS", "no social engineering with real
     employees", "no destructive actions in prod"), and whether prior
     notification is required before exploitation.
   - Show the full scope back to the operator in a table and ask for
     explicit confirmation ("do you confirm this scope?") before saving
     anything. If the operator corrects something, repeat confirmation.

3. **Generate the target card (5 questions).** Format from
   `templates/target-card.md` if the file exists; otherwise use this
   inline structure and, in that case, note that the template is not
   written yet:
   1. What is the target? (product/company/organization, what it does,
      who uses it)
   2. What are the crown jewels? (what data or function, if compromised,
      makes the engagement critical — PII, money, admin credentials,
      etc.)
   3. Who is the contact/authorization? (name, role, reference from
      step 2)
   4. What is explicitly out of scope or prohibited?
   5. What is the engagement window and the time/rate rules?

   Fill the target card with the operator's answers. If any answer is
   ambiguous, ask again — do not infer.

4. **Create the audit directory** with `mkdir -p`:
   ```
   <audit_dir>/
   ├── .pentest-state/
   ├── raw/           # output crudo de herramientas
   ├── evidence/      # PoCs, capturas, request/response
   └── report/        # drafts y reporte final
   ```

5. **Initialize engine state** (uses `engine/state.py` via Python,
   with `${CLAUDE_PLUGIN_ROOT}/engine` in `sys.path`):
   ```bash
   python3 -c "
   import sys; sys.path.insert(0, '${CLAUDE_PLUGIN_ROOT}/engine')
   from state import EngagementState, Phase
   s = EngagementState('<audit_dir>')
   s.initialize('<engagement_id>', '<target>', metadata={'target_card': <dict>})
   print(s.to_dict())
   "
   ```
   Suggested `<engagement_id>`: `<slug>-<YYYYMMDD>`.

6. **Save the scope** with `engine/scope.py`:
   ```python
   from scope import Scope
   sc = Scope(authorization="<referencia>", rules=[...])
   sc.add_in_scope("<pattern>", "<domain|ip|cidr|wildcard>", notes="...")
   sc.add_out_of_scope(...)
   sc.save(Path("<audit_dir>/.pentest-state/scope.json"))
   ```

7. **Persist controls and authority.** Configure `TimeWindowGuard` with
   timezone, windows, and expiration; they are mandatory for network
   actions. Record `CustodyLog.scope_confirmed(...)` with the scope hash
   and the authorization reference. Store secrets only in the encrypted
   vault (`PENTEST_VAULT_KEY` external recommended), never in target
   cards or commands.

8. **Transition the phase** `INIT → SCOPED` with
   `s.transition(Phase.SCOPED)`. If `can_transition` returns `False`
   (should not happen on a new engagement), report it and stop — it is
   a signal of corrupt state, not something to force.

9. **Write the target card** as `<audit_dir>/report/target-card.md`
   (Write tool) with the 5 answers and the resolved scope.

## Expected output

- Confirmation in a table: target, slug, audit dir, current phase
  (SCOPED), in/out scope, authorization reference.
- Path of the written target card.
- Recommended next step: `/quarry:recon` (full, by default).

Do not run any scan, HTTP request, or discovery tool in this command —
`/quarry:engage` only establishes scope and state. Any temptation to
"get ahead" on recon here is explicitly rejected: that is `/quarry:recon`'s
job and must run with scope already persisted and the `hooks/hooks.json`
guard active.
