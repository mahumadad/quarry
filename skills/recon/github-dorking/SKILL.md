---
name: github-dorking
description: >
  Find leaked secrets and internal information in public (and client-provided private) Git
  history: GitHub/GitLab dork queries, and secret-scanning repos with truffleHog/gitleaks for
  API keys, passwords, internal URLs, and config files committed by mistake. Use after
  osint/js-analysis have named the org, product, and employee handles, to search where those
  names appear in code hosting. Do NOT use for scanning JS bundles served by the live app —
  that's js-analysis; this skill is specifically about Git repositories and their history
  (including deleted/rewritten commits), not live application assets.
metadata:
  type: recon
  phase: recon
  tools: [trufflehog, gitleaks, github-search, gitrob]
depends_on: [osint, js-analysis]
feeds_into: []
---

## Signals

- `osint` has named the org, its GitHub/GitLab organization account, and employee handles.
- `js-analysis` found internal hostnames, project codenames, or package names that could
  identify related repositories.
- The client's engagement explicitly covers source-code-hosting exposure (public repos, or
  the client has granted access to private repos for review).
- A prior finding references a technology/framework whose exact version or config might be
  discoverable from the org's own public repos.

## Prerequisites

- Confirmed org name, GitHub/GitLab organization handle, and any known employee usernames
  from `osint`.
- RoE clarity on whether this covers only the org's own public repositories, or also private
  repos the client has granted explicit access to review — scanning a private repo without
  that access is out of scope regardless of how it was discovered.

## Methodology

1. **Enumerate the org's repositories and member accounts** before dorking individual strings —
   a targeted scan across known repos is far more productive than blind global search:
   ```bash
   curl -s "https://api.github.com/orgs/example-corp/repos?per_page=100" | jq -r '.[].full_name'
   curl -s "https://api.github.com/orgs/example-corp/members" | jq -r '.[].login'
   ```

2. **Manual dork queries** against GitHub's code search and `grep.app`/`sourcegraph` mirrors
   (GitHub's own search UI/API has limited scope for code search on some plans — use whichever
   is accessible), targeting the org name, product name, and internal naming patterns:
   ```
   org:example-corp password
   org:example-corp "BEGIN RSA PRIVATE KEY"
   org:example-corp filename:.env
   org:example-corp api_key OR apikey OR secret_key
   "example-corp.internal"
   "example-corp" "AWS_SECRET_ACCESS_KEY"
   ```

3. **Secret-scan every cloned repo's full history with truffleHog**, not just the current
   HEAD — secrets committed and later "removed" in a subsequent commit remain in Git history
   unless the history itself was rewritten:
   ```bash
   trufflehog git https://github.com/example-corp/some-repo --json > trufflehog-results.json
   ```

4. **Gitleaks as a cross-check with a different detector/rule set**, useful for catching
   patterns truffleHog's detectors miss:
   ```bash
   gitleaks detect --source=./some-repo --report-path=gitleaks-report.json
   ```

5. **Gitrob (or equivalent) for org-wide sweep** across every repo + every member's personal
   repos in one pass, when the org is large enough that manual per-repo cloning is impractical:
   ```bash
   gitrob example-corp
   ```

6. **Check forks, archived, and deleted-but-cached repos**, not just the current active repo
   list — a fork of an internal tool, or a repo an employee made public briefly before making
   it private again, can still be indexed by GitHub's search or by third-party mirrors:
   ```
   org:example-corp fork:true
   ```

7. **Check employee personal repos and gists** for anything referencing the org — employees
   frequently commit internal snippets, config fragments, or credentials to personal
   repositories/gists that fall outside the org account entirely:
   ```
   user:employee-handle "example-corp"
   https://gist.github.com/employee-handle
   ```

8. **For every candidate secret found, verify it's live before treating it as a finding.**
   A string that matches a credential pattern is a lead, not a finding (same rule as
   `js-analysis`) — test the credential against the service it appears scoped to (read-only,
   least-impact check) to confirm current validity:
   ```bash
   aws sts get-caller-identity --profile candidate-leaked-key   # confirms the key is live, scope-checked
   ```

9. **Escalate immediately anything confirmed live**, per `opsec-discipline`'s data-handling
   rule — a live production credential found in a public repo is time-sensitive and should not
   sit in a routine findings queue until report time.

## Tooling

GitHub/GitLab code search (web UI or API), `grep.app`/Sourcegraph as search mirrors,
`trufflehog git <repo-url>` (full history), `gitleaks detect --source`, `gitrob` for org-wide
sweeps, `jq` for API response parsing.

## Validation gate

- [ ] Every candidate secret is checked for liveness/validity before being reported as a
      finding, not just pattern-matched.
- [ ] Any confirmed-live credential is escalated immediately per `opsec-discipline`, not left
      for routine reporting.
- [ ] Private-repo access (if any) is confirmed explicitly authorized by the client before
      scanning, separate from public-repo scope.
- [ ] Full Git history was scanned, not just the current HEAD, for every repo in scope.

## Gotchas

- Secret-scanning full Git history, not just HEAD, is the whole point of this skill — a repo
  that looks clean at HEAD can still have a plaintext key three commits back that a
  `git log -p` or a current-state-only scanner would miss entirely.
- Most matched "secrets" in public repos are intentionally public (publishable keys, example/
  placeholder values in documentation, test fixtures) — confirm scope/live-ness before
  reporting, exactly as `js-analysis`'s equivalent caution states.
- A dork query without `org:`/`user:` scoping returns enormous noise from unrelated
  repositories using the same common strings — always scope queries to confirmed org/employee
  identifiers first.
- Deleted repos and force-pushed/rewritten history can still be served from GitHub's search
  index or third-party mirrors for a period after removal — absence from the current repo list
  doesn't mean the content was never indexed.
- Scanning private repos requires the client's explicit access grant for *this* skill, not an
  assumption that general engagement scope covers source code — ask if unclear, per project
  CLAUDE.md scope rules.
