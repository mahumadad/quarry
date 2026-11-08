---
name: quarry:doctor
description: Audit engagement integrity, orphaned tasks, artifacts and references
allowed-tools: Bash(*), Read(*)
---

# /quarry:doctor

Two modes:

## Without active engagement (environment check)

Check the operator's environment for external tool availability:

```python
import sys; sys.path.insert(0, '${CLAUDE_PLUGIN_ROOT}/engine')
from tool_registry import ToolRegistry, TOOL_FALLBACKS, CAPABILITY_BACKENDS
from toolrunner import ToolRunner

runner = ToolRunner('/tmp/quarry-doctor')
reg = ToolRegistry('/tmp/quarry-doctor', runner)
for tool in sorted(set(TOOL_FALLBACKS) | {t for ts in CAPABILITY_BACKENDS.values() for t in ts}):
    result = reg.probe(tool)
    status = "OK" if result["available"] else "MISSING"
    print(f"  {status}: {tool} — {result.get('version', 'n/a')}")
```

Report: available tools, missing tools with fallback suggestions, and
capabilities that have no backend installed at all.

## With active engagement (full audit)

Run `python3 -m engine.orchestrator doctor --audit-dir <audit_dir>` and
additionally check that all JSON files in `.pentest-state` are parseable.

Report separately: corrupt state, orphaned `running` tasks, completed
tasks without timestamp, missing/altered artifacts, broken custody chain,
findings without evidence, declared outputs that are absent, secrets
outside the vault. Include `tool_unavailable` capabilities from the
registry, wordlists whose SHA-256/size changed, and memory statistics.
The retention policy of `memory_maintenance.py` is explicit and archives
before pruning; doctor does not delete memory or evidence on its own.
Do not auto-repair or overwrite corrupt evidence or state.
