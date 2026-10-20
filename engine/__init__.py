"""
Pentest Plugin Engine — deterministic state management (no LLM).

Modules:
  state         Engagement state machine
  scope         Scope tracking and validation
  findings      Finding lifecycle (detected → confirmed → exploited → chained → validated → reported)
  chain_engine  Chain matrix + pivot graph for finding composition
  rebuttal      Generator ↔ Checker adversarial validation loop
  budget        Tool call limits and timeouts
  loop_detector Anti-loop detection
  coverage      Coverage tracking by vuln class × asset
  guard         PreToolUse command guard
"""
