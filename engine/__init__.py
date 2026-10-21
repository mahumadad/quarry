"""
Pentest Plugin Engine — deterministic state management (no LLM).

Modules:
  state         Engagement state machine
  scope         Scope tracking and validation
  findings      Finding lifecycle + evidence integrity (SHA-256) + hunt mode gating
  chain_engine  Chain matrix + pivot graph + capability graph for finding composition
  rebuttal      Generator ↔ Checker adversarial validation + blind re-exploit mode
  budget        Tool call limits, timeouts, cost/ROI tracking
  loop_detector Anti-loop detection
  coverage      Coverage tracking by vuln class × asset
  guard         PreToolUse command guard
  app_profile   Mandatory pre-hunt target intelligence
  brain         Capability graph, exhaustion tracking, engagement intelligence
  vault         Credential storage for engagement test accounts
  router        Deterministic engagement type → skill routing
"""
