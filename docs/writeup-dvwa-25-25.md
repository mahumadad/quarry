# DVWA 25/25: What "100% recall" actually means when every finding has to prove itself

> A benchmark writeup for [Quarry](https://github.com/mahumadad/quarry) — a full-cycle
> penetration-testing plugin for Claude Code. **Track. Aim. Prove.**

Most AI security tools brag about how many vulnerabilities they find. Quarry is
built around a different number: how many it can *prove*. This is the story of
one benchmark run — Damn Vulnerable Web Application, scored 25 out of 25 — and,
more importantly, what had to be true for each of those 25 to count.

The headline is easy: **25 expected, 25 found, 100% recall, 100% precision, 100%
evidence integrity.** The interesting part is everything underneath it.

---

## 1. Setup

DVWA is the oldest cliché in the training-target catalog, and that is exactly
why it is a good regression baseline: the vulnerability set is stable,
well-documented, and spans the classic web classes without SPA or API noise to
hide behind.

| Item | Value |
|---|---|
| Target | [digininja/DVWA](https://github.com/digininja/DVWA), `master` branch |
| Runtime | PHP 8.5.9 (native) + MariaDB, local |
| URL | `http://localhost:8080` |
| Security level | `low` (the reproducible baseline — see note) |
| Authorization | Operator-owned instance, stood up specifically for the benchmark |
| Date | 2026-10-22 (scored 18:12 UTC) |

A few deliberate choices:

- **`security=low` is the baseline, not a shortcut.** DVWA ships four difficulty
  levels. The benchmark pins `low` so the run is reproducible between plugin
  versions — the KPI is *recall drift over time*, which only means something if
  the target never moves. Where a module's behavior depends on the level (the
  authorisation-bypass endpoint, for instance, enforces its role check only at
  `high`/`impossible`), the finding records that dependency instead of
  pretending it is unconditional.
- **The ground truth is frozen.** The 25 expected findings live in
  [`benchmarks/targets/dvwa.yaml`](../benchmarks/targets/dvwa.yaml), curated by
  hand against the DVWA module list and cross-checked with the upstream repo.
  The rule in the harness is strict: *the ground truth is never edited to make a
  run pass.* If the plugin finds something real that is missing from the YAML,
  it gets audited and added in a separate commit, with justification.
- **Two of the 25 are marked `optional`** (CSP bypass, which can need an
  externally-reachable allowed origin, and the exposed `.git` directory, which
  is a deployment artifact rather than a DVWA bug). They still have to be *found*
  to score, but they never cover for a missed required item. Both were found
  anyway.

Scoring is done by [`benchmarks/score.py`](../benchmarks/score.py), which
compares the engagement's `findings.json` against the target YAML and emits
recall, precision, and evidence-integrity numbers. Two of its rules matter for
reading the result honestly:

- **Only `validated` or `reported` findings count toward recall.** Leads,
  hunches, and half-confirmed hypotheses are explicitly excluded — "a lead is
  not a result."
- **A single real vulnerability cannot satisfy two ground-truth entries.** Once
  a finding is matched to an expected item, it is taken out of the pool. No
  double-counting to inflate recall.

---

## 2. The engagement

Quarry runs an engagement as a sequence of phases, each gated and each writing
to an append-only state directory. For this run the lifecycle was:

```
Scope ──► Recon ──► Hunt (breadth-first) ──► Validate ──► Report
```

**Scope (03:56 UTC).** The engagement opens with an operator-confirmed scope
entry — the very first line of the custody log:

```json
{"event": "scope_confirmed",
 "detail": {"target": "http://localhost:8080 (DVWA master, PHP + MariaDB, security=low)",
            "authorization": "operator-owned instance for plugin benchmark"},
 "actor": "operator",
 "prev_hash": "0000…0000"}
```

Nothing offensive runs before this. No scope, no actions — that rule is injected
into every session and is not optional.

**Recon → Hunt.** Hunting is deliberately **breadth-first**: cover every
vulnerability class before going deep on any one of them, and open two or three
independent attack paths before committing. Dead ends are logged as information,
not swept away. The run captured findings in two waves — a first batch of nine
core-class findings (SQLi, XSS, command injection, upload, LFI, CSRF, brute
force) during the initial pass, then a deeper wave of sixteen covering DOM-based
and client-side issues, session handling, the REST API, and platform-level
exposure.

**Validate.** Every candidate had to walk the status ladder
`detected → confirmed → validated` before it was allowed into the report. Each
transition is recorded with a reason:

- `detected → confirmed`: *"reproduced against local DVWA (security=low)"*
- `confirmed → validated`: *"impact demonstrated with captured evidence"*

A finding that cannot produce a reproducible trigger does not reach `validated`,
and anything short of `validated` does not score. This is the gate that turns
"the scanner flagged it" into "we proved it."

**Report.** The final state — 25 validated findings, 30 evidence artifacts — was
exported and the export itself written to the custody chain.

---

## 3. The 25 findings

All 25 are tagged **Demonstrated**: each has a reproducible proof-of-concept —
a request/response pair, tool output, or a runtime observation — not an inference
from a version banner.

| # | Vuln class | CWE | Sev | Evidence | What was proven |
|---|---|---|---|---|---|
| 1 | SQLi | CWE-89 | High | Demonstrated | `?id=' OR 1=1-- -` returns every user row (admin, Brown, …) |
| 2 | SQLi (blind) | CWE-89 | High | Demonstrated | Time-based: `AND SLEEP(3)` → 3.1 s vs 0.057 s control (~54×) |
| 3 | XSS (reflected) | CWE-79 | Med | Demonstrated | `name=<script>…</script>` reflected verbatim in the response |
| 4 | XSS (stored) | CWE-79 | High | Demonstrated | Guestbook `mtxMessage` persists and is served raw to every visitor |
| 5 | Command injection (RCE) | CWE-78 | **Crit** | Demonstrated | `ip=127.0.0.1;id` → `uid=501` in the output |
| 6 | File upload | CWE-434 | High | Demonstrated | `shell.php` as `image/jpeg` accepted, served executable, `?cmd=id` → `uid=501` |
| 7 | LFI | CWE-98 | High | Demonstrated | `page=../../../../etc/passwd` returns the `root:` line |
| 8 | CSRF | CWE-352 | Med | Demonstrated | Password changed via GET with no token/re-auth; fresh login verified, then restored |
| 9 | Rate limiting | CWE-307 | Low | Demonstrated | 15 failed logins — no lockout, captcha, or delay |
| 10 | XSS (DOM) | CWE-79 | Med | Demonstrated | `document.write` of a raw URL substring; `alert` fired in headless Chromium |
| 11 | Session management | CWE-330 | Med | Demonstrated | `dvwaSession` is an incremental counter (1, 2, 3) |
| 12 | Auth bypass (CAPTCHA) | CWE-287 | Med | Demonstrated | POST straight to `step=2` changes the password with no CAPTCHA (restored) |
| 13 | XSS (CSP bypass) | CWE-693 | Med | Demonstrated | `script-src` allows jsdelivr/unpkg/pastebin; external-script `alert` fired |
| 14 | Business logic | CWE-602 | Low | Demonstrated | Client-side token `md5(rot13(phrase))` computed offline → "Well done" |
| 15 | Open redirect | CWE-601 | Low | Demonstrated | `redirect=https://example.com/evil` → `302 Location:` to it |
| 16 | Auth bypass (missing authz) | CWE-862 | High | Demonstrated | Admin user-data endpoint returns the full list to a customer session |
| 17 | Broken access control | CWE-639 | High | Demonstrated | Authz compares `$_GET` vs `$_COOKIE` user_id; forged cookie → admin profile |
| 18 | Weak cryptography | CWE-327 | Med | Demonstrated | XOR + base64 with a hardcoded key; decoded offline, login succeeds |
| 19 | API abuse (no auth) | CWE-306 | High | Demonstrated | `/v2/user/` lists users and `POST` creates one (201) with no token |
| 20 | Default credentials | CWE-521 | High | Demonstrated | `admin/password` works on the first try |
| 21 | Info disclosure | CWE-200 | Low | Demonstrated | `phpinfo.php` exposes PHP 8.5.9 and full config |
| 22 | Weak password hash | CWE-916 | Med | Demonstrated | MD5 unsalted; admin hash = `md5('password')` exactly |
| 23 | Session management | CWE-1004 | Low | Demonstrated | `dvwaSession` cookie has no HttpOnly/Secure/SameSite |
| 24 | Info disclosure (.git) | CWE-527 | Med | Demonstrated | `/.git/config` served (200) — deployment artifact |
| 25 | CORS | CWE-942 | Low | Demonstrated | `Access-Control-Allow-Origin: *` with GET/POST/PUT/DELETE on the API |

**Severity split:** 1 critical · 9 high · 9 medium · 6 low.

Worth noticing: findings 5 and 6 both reach RCE, and the run proved it the way a
real engagement would — the command-injection PoC and the uploaded webshell both
returned the *same* live `uid=501(…)` from the host, not a theoretical "this
could allow code execution." Finding 8 (CSRF) and finding 12 (CAPTCHA bypass)
each changed a real password to confirm impact, verified a fresh login with the
new value, and then **restored the original** — state-changing proof, cleaned up
after itself, logged both ways.

---

## 4. Evidence discipline

This is the part that does not show up in a recall number, and it is the whole
point of the project.

### Every claim is tagged

Quarry's anti-fabrication rules require every finding to carry one of three tags:

- **Demonstrated** — a working PoC.
- **Inferred** — partial evidence (e.g. a blind finding without a correlated
  out-of-band callback is capped here).
- **Unproven** — a hypothesis, which does not ship as a finding.

All 25 DVWA findings are **Demonstrated**. "Could allow X" is not a finding in
this model; it is a hypothesis that still has to be verified.

### Every artifact is hashed

`findings.json` holds **30 evidence blobs** across the 25 findings (some findings
carry two — the upload has both the accepted-upload response and the webshell's
`id` output; the crypto finding has both the ciphertext blob and the successful
login). Every one of the 30 is independently SHA-256'd at capture time. The
scorer's evidence-integrity metric is simply: of all evidence attached to matched
findings, what fraction carries a hash?

```json
"evidence": { "total": 30, "hashed": 30, "integrity": 1.0 }
```

30 of 30. No un-hashed evidence reached the report.

### The custody chain ties it together

Hashing a blob proves *that artifact* wasn't altered. It does not prove the
*sequence* of events — when scope was confirmed, in what order evidence was
captured, when the report was exported. That is what the custody log
([`engine/custody.py`](../engine/custody.py)) adds: an append-only,
hash-chained record where each entry carries the hash of the one before it.

For this run the chain is **28 events**:

```
scope_confirmed      ×1   (actor: operator, prev_hash = 0000…0000)
evidence_captured    ×25  (actor: agent — one per finding)
export               ×2   (actor: agent)
```

Each entry hashes `{event, detail, actor, timestamp, prev_hash}`. Change any
field in any past entry — a timestamp, a finding id, the scope authorization —
and that entry's hash no longer matches, *and* every subsequent `prev_hash`
points at a value that no longer exists. The tampering isn't just detectable; it
is localizable to the exact line. Walking the DVWA chain end to end:

```
entries:   28
intact:    true
head hash: 0c4093eaa28c5d9d621432a3c4524b1d8af1efbf6d4e17d58fa1013fdcb20bfc
```

That genesis `prev_hash` of 64 zeros, the per-finding capture events, and the
sealed head hash are what let a report say more than "we found X." They let it
say: *here is the tamper-evident record of when, how, and under what
authorization each action was taken* — the thing procurement, legal, and
compliance actually ask for.

---

## 5. "We found 47" vs "25, proven"

Point any unfiltered scanner at a target like this and you will get a big
number. Every version banner becomes a CVE match. Every missing response header
becomes a line item. The same underlying issue gets reported once per module it
appears in. You can hit forty-something "findings" without trying — and then a
human still has to sit down and work out which ones are real, which are
duplicates, and which are noise. The volume is the easy part; the triage is the
cost you actually pay.

Quarry inverts that. Nothing ships as a finding until it has a reproducible
trigger and hashed evidence behind it, so the number you get out is already the
triaged number:

| | Volume-first tooling | Quarry on DVWA |
|---|---|---|
| Reported items | "47" (raw, pre-triage) | 25 |
| Backed by a working PoC | unknown until a human checks | 25 / 25 |
| False positives / duplicates | triage problem left to you | 0 (precision 1.0) |
| Tamper-evident evidence trail | — | 28-event hash-chained custody log |
| What a reader has to take on faith | which ones are real | nothing — every claim replays |

That **precision 1.0** is worth being precise about, because it is a benchmark
result, not a universal promise: on this run, every finding that reached
`validated` matched a distinct ground-truth entry — zero unmatched, zero
duplicates, zero invented. It does not mean Quarry can never produce a false
positive in the wild. It means that on a target with known, frozen ground truth,
the discipline held: the tool reported exactly the real issues and nothing it
could not stand behind.

25 you can hand to a client beats 47 you have to apologize for.

---

## 6. Try it

Quarry is open source (MIT) and the DVWA result is fully reproducible — the
ground truth, the scorer, and the raw run state are all in the repo.

- **Repo:** <https://github.com/mahumadad/quarry>
- **This result:** [`benchmarks/results/2026-10-22-dvwa.json`](../benchmarks/results/2026-10-22-dvwa.json)
- **Ground truth:** [`benchmarks/targets/dvwa.yaml`](../benchmarks/targets/dvwa.yaml)
- **Scorer:** [`benchmarks/score.py`](../benchmarks/score.py)
- **Custody engine:** [`engine/custody.py`](../engine/custody.py)

Stand up your own DVWA, run an engagement against it, and score it:

```bash
python3 benchmarks/score.py \
  --target benchmarks/targets/dvwa.yaml \
  --findings /path/to/engagement/.pentest-state/findings.json \
  --out benchmarks/results/$(date +%F)-dvwa.json
```

Same story holds on the other targets: crAPI 10/10 and Juice Shop v20.3.0 14/14,
both at 100% recall and 100% evidence integrity. DVGA, VAmPI, and WebGoat are
next.

> **Authorized engagements only.** Quarry is for penetration tests performed
> under written authorization. The MIT license grants permission to use the
> software — not permission to test systems you do not own or have explicit
> authorization to test.

*Track. Aim. Prove.*
