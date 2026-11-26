# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **New `hunt/invariant-violation` skill:** meta-hunting methodology for
  systematically finding broken assumptions — immutability violations,
  cross-component disagreement, trust boundary shifts, teardown/cleanup
  incompleteness, temporal/ordering assumptions, and allowed-but-risky
  patterns (eval of "sanitized" input, deserialization of "trusted" data).
  Includes timing-oracle statistical validation (R² linearity for blind
  confirmation), payloads-as-structured-tests table, and bypass techniques
  against common defenses (client-side validation, WAF-only protection,
  cache TTL, partial logout). Informed by XBOW's Chrome full-chain,
  EAC calculator RCE, CVE-2026-72018 (kernel SMC-D), and CVE-2026-45185
  (Exim UAF) research.
- **`hunt/graphql` enriched with big-tech bounty patterns (steps 8–11, anchors 6–8):**
  Relay-convention mutation mapping (extract `fb_api_req_friendly_name` from
  JS bundles), input parameter IDOR on mutations (`media_set_id` pattern
  with missing ownership checks), client-supplied identity override
  (`actor_id`), multi-subdomain GraphQL surface discovery, incomplete fix
  exploitation on sibling mutations, and cross-tenant mutation IDOR. New
  Payloads rows (5) and Bypass rows (3). Informed by Meta AI ($10K
  media_set_id IDOR), Meta support system ($78K case_id IDOR), and TikTok
  Ads cross-tenant pixel events IDOR.
- **`hunt/idor` enriched with GraphQL mutation vector (signal + anchor 6):**
  GraphQL mutation input parameters (`media_set_id`, `pixel_id`, `actor_id`)
  as IDOR surface, cross-referencing `graphql` step 9.
- **`hunt/deserialization` enriched with signed-cookie forge chain (step 7):**
  signed-but-not-encrypted session cookie inspection (Flask itsdangerous,
  Django PickleSerializer), self-revealing secret recovery pattern (signing
  key embedded in the cookie's own payload), timing-based blind pickle
  confirmation (time.sleep correlation over 3+ data points), and new chain
  anchor for secret-recovery → forge → deserialize escalation. Informed by
  the Google DevSite Flask session pickle RCE writeup ($90k bounty).
- **`hunt/xxe` enriched with translation file vectors (step 9, anchors 5–6):**
  translation/localization import features (XLIFF, Android XML, .resx,
  stringsdict) as XXE surface — each format uses a distinct parser code path,
  so multi-format import multiplies entry points. New chain anchors for
  multi-format surface testing and multi-tenant SaaS escalation (cloud
  metadata, cross-tenant credential recovery). Informed by CVE-2026-32251
  (Tolgee XXE via translation import).
- **`hunt/race-condition` enriched with state-transition TOCTOU (step 9):**
  non-concurrent TOCTOU pattern — mutate validated state between workflow
  steps without needing a concurrency burst (email verification swap,
  payment authorization gap, file upload pipeline replacement).
- **Extended chain-engine oracle set (13 new oracles):** `chain_exploit.py`
  now composes chains for `jwt-forgery`, `oauth-misconfig`, `saml-forgery`,
  `nosqli`, `graphql-introspection`, `mass-assignment`,
  `subdomain-takeover`, `host-header-injection`, `cache-poisoning`,
  `http-smuggling`, `prototype-pollution`, `ldap-injection` and
  `password-reset-poisoning`, each with produces/consumes capabilities,
  an oracle check and evidence keys. Hunt-skill slugs (`jwt`, `oauth`,
  `saml`, `2fa-bypass`, `403-bypass`, ...) alias to their oracle class so
  findings from those skills enter chain composition. New chains that now
  close: jwt→mass-assignment (admin_session), oauth→mass-assignment,
  password-reset→credential-reuse, saml→privesc, nosqli→idor,
  http-smuggling→ssrf→cloud-metadata (critical),
  ldap-injection→credential-reuse (critical).
  `tests/test_chain_oracles_ext.py`.
- **AI red-team extended payload families and templates:** six new
  INJECTION_PAYLOADS families (`encoded_bypass`, `agentic_memory`,
  `tool_schema_abuse`, `system_prompt_leak`, `rag_corruption`,
  `multi_agent_channel`) and five new builtin templates
  (`encoded_bypass_test`, `agentic_memory_test`, `tool_schema_test`,
  `system_prompt_leak_test`, `multi_agent_channel_test`), all canary-gated
  and framework-mapped. `tests/test_ai_red_team_ext_payloads.py`.
- **AD/cloud hunt technique updates:** `ad-pentest.yaml` hunting phase now
  enumerates ADCS ESC1-ESC8, RBCD, NTLM relay/coercion, Shadow
  Credentials, ACL abuse paths, gMSA/LAPS reads and DPAPI backup keys;
  `cloud-pentest.yaml` adds identity-plane techniques (Entra/Okta token
  theft, consent grants), IMDSv2 downgrade, GCP/Azure metadata variants,
  container/CI escape paths, and the `entra-attack`/`okta-attack` skills,
  plus `jwt`, `nosqli`, `host-header` priority classes.
- **Missing vuln-class priors:** `403-bypass` (0.73) and `csrf` (0.58)
  now have explicit weights in `vuln_class_weights.py` — they previously
  fell to the 0.5 default even though both are chain pivots.

### Changed
- **Validation gate now requires rebuttal (fix #1):** `FindingsStore.update_status`
  refuses the transition to VALIDATED unless `rebuttal_result == "ACCEPTED"`.
  Previously the FSM only checked evidence, evidence_tag and steps_to_reproduce,
  allowing a finding to reach VALIDATED without adversarial rebuttal.
- **three_gate verdict renamed (fix #2):** `verify_finding` now returns
  `anomaly_detected` instead of `confirmed` to make explicit that the 3-gate
  protocol detects response anomalies, not vulnerability confirmation.
  `verify_and_record` and chain_exploit consumers updated accordingly.
- **README: action section corrected (fix #3):** the CI action section now
  accurately describes the GitHub Action as a plugin self-check, not a
  PR-level target scanner.
- **Benchmarks: reproducibility framing (fix #4):** benchmark results are
  now explicitly labeled as historical operator-run snapshots with a note on
  what metadata is needed for reproducible claims.
- **Custody: scope disclaimer (fix #5):** `engine/custody.py` docstring and
  README now document that the chain is tamper-evident (detects casual
  modification) not tamper-proof, with pointers to stronger guarantees.

### Fixed
- `skills/recon/surface-probes/SKILL.md`: frontmatter `feeds_into: [*]`
  was an invalid YAML alias (the file failed to parse as YAML; the plugin
  loader skipped it silently). Now `feeds_into: [hunt/*]`.
- `engine/oast.py`: interactsh session leaked the log file descriptor for
  the whole engagement; the fd is now closed right after spawn (the child
  keeps its own copy).
- `engine/ai_red_team.py`: `find_escalation_paths` queried trust
  boundaries it never used; removed the dead query.
- `engine/ai_red_team_ext.py`: `_whitespace_inject` embedded a literal
  zero-width space in source; it is now an explicit `"\u200b"` escape
  (invisible-character-in-source bug class, ruff PLE2515).
- `engine/chain_engine.py` / `engine/mcp_supply_chain.py`: unused locals
  removed (ruff F841).
- `engine/ai_red_team.py` / `engine/mcp_client.py`: mutable class-default
  constants annotated as `ClassVar` (ruff RUF012).

### Added
- **Modern WAF-evasion techniques (2026 research):** `defense_evasion.py` gains
  the body-size inspection-window bypass (`oversized_body_pad` / `WAFBypassEngine.
  generate_oversized_body`, the nowafpls technique both field guides rank #1),
  Cyrillic/Latin `homoglyph` and multi-character-entity (`&nvlt;`/`&nvgt;`)
  transforms, and the full trusted-client-IP header set (adds `True-Client-IP`,
  `CF-Connecting-IP`, `X-Originating-IP`, `Forwarded`). Skills document RFC 2231
  `filename*` (CVE-2026-104269) in `file-upload`, HTTP/2 Stream Parser Confusion
  (SPCA, WWW 2026) in `http-smuggling`, the body-size/method-flip bypass in
  `parser-desync`, and origin-IP-behind-WAF discovery in `waf-fingerprint`.
  `tests/test_defense_evasion.py`.
- **Noise governor (`engine/pacing.py`):** an operator-chosen pacing dial
  (`off`/`quiet`/`balanced`/`aggressive`) that injects each tool's rate ceiling
  (`nmap --max-rate`, `ffuf -rate -p`, `nuclei -rl/-c`, `httpx/katana -rate-limit`,
  `masscan/sqlmap/dalfox/...`) proactively — complementing the reactive
  `AdaptiveThrottle`. Wired into `engine/fanout.py` and `engine/nuclei_runner.py`
  via `--pacing`; `off` is a true no-op that never fights a limit a command
  already sets. Documented in the `opsec-discipline` skill. `tests/test_pacing.py`.
- **Recon tool ingestion:** `tool_ingest` now parses `nmap` (`-oX` XML, open ports
  only), `httpx` (`-json` JSONL), `ffuf` (`-o json`) and `bbot` (NDJSON, filtered
  by scope distance) into OPEN leads (never findings); nmap/burp DOCTYPE stripped
  against entity-expansion. `tests/test_tool_ingest.py`.
- **Claude-BugHunter content port (mixed approach):** `## Payloads & Detection Patterns` and
  `## Bypass Techniques` tables plus reinforced chain anchors across 44 hunt skills. Taxonomy
  adapted from the disclosed-report corpus; payloads written fresh under the house
  Demonstrated/Inferred/Unproven discipline.
- **Framework-specific hunt skills:** `hunt/nextjs`, `hunt/nodejs`, `hunt/aspnet`, `hunt/laravel`,
  `hunt/springboot`, plus `hunt/403-bypass`. Version-only CVE matches stay Unproven until a
  trigger is reproduced.
- **New vuln-class hunt skills:** `hunt/nosqli`, `hunt/ldap-xpath-injection`, `hunt/captcha-bypass`,
  `hunt/dom-based`, `hunt/shadow-api`, `hunt/ntlm-info-disclosure`, `hunt/exceptional-conditions`.
- **Perimeter/identity platform skills:** `platform/okta-attack`, `platform/entra-attack`,
  `platform/ssl-vpn-appliances`, `platform/vcenter-attack`, `platform/sharepoint-onprem`.
- **Vuln-class yield ranking:** `engine/vuln_class_weights.py` weights hunt classes by real-world
  impact/frequency; `router.get_hunt_priority` orders within each bucket by it (brain-suggestion
  and coverage-gap precedence preserved). New classes wired into the web-app/api workflows with a
  `tests/test_wiring.py` orphan guard. `tests/test_vuln_class_weights.py`.
- **Burp Scanner ingestion:** `tool_ingest.parse_burp` turns a Burp Scanner XML export into OPEN
  leads (never findings); the DOCTYPE is stripped so a crafted file cannot smuggle an
  entity-expansion bomb. `tests/test_tool_ingest.py`.
- **Scope rule normalization:** a `domain` scope rule authored with a `:port`, scheme, `/path` or
  trailing dot now matches the host, closing a fail-open into a broader in-scope rule.
  `tests/test_scope_matching.py`.
- **LLM judge robustness:** `judge_response` takes the last parseable JSON object (surviving
  fences, prose and a draft object), coerces confidence to `[0,1]` and ignores a model-forged
  `self_graded`; a failed/empty response never becomes a verdict. `tests/test_ai_red_team_fixes.py`.
- **Evidence hygiene:** HAR/PCAP capture-file sanitization step and gate check (strip auth
  headers, cookies, session IDs, PII; slice to the cited entries before bundling).
- **Guard/tripwire hardening:** `command_policy` is a no-op outside an engagement (no
  `.pentest-state/`), fails closed on parse errors, and detects adjacency/substitution/inline-code
  bypasses (`;`, `$()`, backticks, `&&`/`||`/`|`, `/dev/tcp`); `BLOCKED_ALWAYS` matches by token.
  `tests/test_guard_hardening.py`.
- **Scope matching hardening:** host-only matching (ports stripped), CIDR/range in scope only when
  fully contained and non-overlapping with out-of-scope, host/path split, wildcard-on-host,
  IPv6/hex forms, and recovery of hosts embedded in tool syntax (`ssh user@`, `socat TCP:`,
  `bash -c`). `tests/test_scope_matching.py`.
- **Offensive skills:** `hunt/authz-matrix` (multi-identity authorization sweep), `hunt/saml`
  (XSW, signature stripping, assertion replay, RelayState), `hunt/parser-desync` (JSON/multipart/
  encoding/path discrepancies across layers), `recon/historical-endpoints` (Wayback/gau/CDX/
  Common Crawl/source-map/git pipeline with live-probe). New vuln classes `saml`, `parser-desync`
  in `coverage.py`.
- **Skill augmentations:** `hunt/race-condition` single-packet (HTTP/2 + last-byte sync) and
  OTP/2FA counter race; `hunt/oauth` OIDC id_token validation, token confusion, refresh/prompt;
  `core/oob-interactions` points to new `references/oob-infra.md` (self-hosted interactsh recipe).
- **Differential retest (`engine/retest.py`):** auto-fires a prior finding's stored HTTP PoC
  through `ProtectedHTTPClient` (current-scope validation + single-use operator approval gate via
  `grant_retest`), classifies fixed / not_fixed / regressed / inconclusive, and persists per
  finding to `.pentest-state/retest.jsonl` for cross-run regression detection. Out-of-scope and
  destructive PoCs are never auto-fired. Wired into the `retest` command/workflow.
  `tests/test_retest.py`.

### Fixed
- **Policy engine hardening (C3):** command_policy() now tokenizes full commands, unwraps
  shell wrappers (bash -c, env, sudo), and covers ssh/openssl/socat/telnet
- **Artifact immutability (C4):** artifact IDs use UUID instead of content-derived hashes;
  paths include timestamps; existing artifacts are never overwritten
- **Finding evidence gate (C5):** new findings must start as `detected`; transition to
  `validated` requires evidence and a non-unproven tag; exporters double-check evidence
- **CI action reliability (C6):** removed `|| true` from validator/test steps; fixed output
  parsers to match actual format; removed bare except in SARIF generation
- **Network scope enforcement (I1):** browser navigation, browser-verify probes, and MCP
  tool calls now validate URLs against PolicyEngine scope
- **Broken skill/workflow references (I2):** fixed 38+ stale references across 31 files;
  created 4 missing closeout skills; added skills→skills validator
- **CVSS 4.0 as primary (I7):** finding-validator, seven-question-gate, finding-discipline,
  and finding-template updated; CVSS 3.1 kept as optional
- **Custody chain description (I9):** updated from "attestable" to "locally tamper-evident"
- **Benchmark claims (I10):** README clarifies results are from manual runs, not automated CI
- **Guard/policy hardening (review):** `bash -c 'shutdown...'`-style inline code is now
  re-tokenized before BLOCKED_ALWAYS matching; subshell `(` added to metachar normalization;
  ping/dig/nslookup/host/whois/traceroute added to NETWORK_TOOLS; commands issued from
  engagement subdirectories resolve the engagement root instead of failing with a bogus
  "scope not configured"; single-use approvals are consumed atomically (no replay window);
  purely local interpreter commands (python3 -m pip, node script.js) no longer false-positive
  as network actions.
- **Async tool runner hardening:** AsyncToolRunner now routes every submitted command through
  command_policy inside an engagement, enforces the 1200s hard timeout, and kills the whole
  process group on timeout.
- **Provider redaction:** public 172.x.x.x IPs (e.g. 172.217.x.x) are now anonymized before
  leaving to LLM providers (the old prefix check only exempted the real 172.16/12 private
  range).
- **Evidence integrity:** custody verify() survives corrupt/torn log lines and reports the
  break instead of raising; Finding.updated_at survives reloads; browser navigate marks
  success only for HTTP < 400; XSS dialog verification requires the canary in the message;
  clickjacking frame detection no longer breaks on redirects.
- **Chain engine correctness:** empty vuln_class no longer matches every known chain;
  chains.json corruption no longer crashes the constructor; re-analysis no longer duplicates
  chains.
- **WAF profile fail-safe:** an unrecognized WAF now falls back to a conservative generic
  profile instead of full-speed "none".
- **OAST correlation:** interactsh callbacks correlate via correlation-id (full-id's first
  segment is the client suffix, not the interaction correlator); token/interaction state
  writes are atomic under the engagement lock; interactsh_start has a real readline deadline
  and never leaves orphan processes.
- **MCP client hardening:** stdio servers launch with a minimal environment (no operator
  secrets inherited) and an executable allowlist; JSON-RPC responses are matched by request
  id and JSON-RPC errors raise instead of returning as results.
- **MCP supply chain coverage:** static check names map to catalog vectors
  (description_injection → tool_description_injection) so coverage and exported OWASP/MITRE
  mappings are correct; load_manifest tolerates null serverInfo.
- **Docs sync:** README counts updated (135 skills / 70 engine modules / 15 workflows /
  19 commands, Python 3.12), CLAUDE.md translated to English, 13 stale skill references in
  commands/agents fixed.

### Changed
- **Language unification (I3):** all commands, workflows, and phase descriptions translated
  from Spanish to English for public repo consistency
- **Vuln class counts (I6):** removed hardcoded counts from commands to prevent drift
- **Agent wiring (I4):** 11 previously unwired agents now assigned to workflows
  (engagement-planner, network-analyst, browser-verifier, ai-agent-exploit, 6 SAST agents)
- **Finding-checker blindness (I5):** documented as prompt-level directive (no runtime
  enforcement yet)
- **plugin.json (I8):** added mcpServers.browser-verifier declaring Claude Browser tool
  dependencies
- Removed absolute claims from README intro
- Archived outdated TODO-REVIEW.md

### Added
- `url_policy()` function for shared URL scope validation
- `check_skill_deps()` validator for skills→skills reference integrity
- 4 closeout skills: artifact-cleanup, credential-hygiene, evidence-seal, data-retention
- SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, pyproject.toml

## [0.1.0] - 2026-10-15

Initial release with full pentest lifecycle: recon, mapping, hunting, chaining,
validation, reporting, and closeout. 18 commands, 14 workflows, 18 agents,
46+ hunt skills, and engine modules for policy, artifacts, findings, custody,
coverage, chains, OAST, and browser verification.
