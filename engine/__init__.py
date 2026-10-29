"""
Pentest Plugin Engine — deterministic state management (no LLM).

Modules:
  state           Engagement state machine
  scope           Scope tracking and validation
  findings        Finding lifecycle + evidence integrity (SHA-256) + hunt mode gating
  chain_engine    Chain matrix + pivot graph + capability graph for finding composition
  rebuttal        Generator ↔ Checker adversarial validation + blind re-exploit + reconciliation
  budget          Tool call limits, timeouts, cost/ROI tracking
  loop_detector   Anti-loop detection
  coverage        Coverage tracking by vuln class × asset
  guard           PreToolUse command guard
  app_profile     Mandatory pre-hunt target intelligence
  brain           Capability graph, exhaustion tracking, engagement intelligence
  vault           Credential storage for engagement test accounts
  router          Deterministic engagement type → skill routing
  checkpoint      Checkpoint/resume for interrupted engagements
  cost_estimator  Pre-engagement cost and token estimation
  target_diff     Target change detection between scans
  oast            Out-of-band interaction tracking for blind vuln confirmation
  sessions        Multi-account session management (IDOR / access-control testing)
  knowledge       Cross-engagement technique effectiveness memory (anonymized)
  custody         Chain-of-custody: append-only hash-chained evidence log
  toolrunner      Tool execution backends (local / Kali REST / Docker) + CLI rules
  exporters       Machine-readable exports: SARIF 2.1.0, JSON (ticketing), CSV
  storage         Atomic writes, engagement locks and corruption detection
  artifacts       Complete raw evidence, provenance, hashes and redacted views
  policy          Shared fail-closed scope/time/approval enforcement
  http_client     Policy-enforcing HTTP client with redirect blocking
  orchestrator    Canonical runs, journal, gates, recovery and resume
  redaction       Central secret redaction for logs, views and exports
  nuclei_templates Hash-locked custom template policy and AppProfile selection
  nuclei_runner   Scoped, risk-gated Nuclei execution and JSONL evidence
"""
