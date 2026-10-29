"""Fail-closed PreToolUse guard for network/destructive Bash commands."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .policy import PolicyDenied, command_policy
except ImportError:
    from policy import PolicyDenied, command_policy

BLOCKED_ALWAYS = ("shutdown", "reboot", "halt", "poweroff", "init 0", "init 6")


def check_command(command: str, scope_file: str | None = None,
                  audit_dir: str | None = None, approved_digest: str = "") -> dict:
    """Backward-compatible API. scope_file selects the engagement containing it."""
    lowered = command.lower()
    for marker in BLOCKED_ALWAYS:
        if marker in lowered:
            return {"allowed": False, "warnings": [],
                    "blocked_reason": f"Blocked: '{marker}' is never allowed"}
    root = audit_dir or (str(Path(scope_file).parent.parent) if scope_file else ".")
    try:
        return command_policy(command, root, approved_digest)
    except PolicyDenied as exc:
        return {"allowed": False, "warnings": [], "blocked_reason": str(exc)}
    except Exception as exc:
        return {"allowed": False, "warnings": [],
                "blocked_reason": f"Policy engine failure; fail-closed: {type(exc).__name__}: {exc}"}


def main():
    parser = argparse.ArgumentParser(description="Pentest command guard")
    parser.add_argument("--command", required=True)
    parser.add_argument("--scope-file")
    parser.add_argument("--audit-dir", default=".")
    parser.add_argument("--approval", default="")
    args = parser.parse_args()
    result = check_command(args.command, args.scope_file, args.audit_dir, args.approval)
    print(json.dumps(result))
    if not result["allowed"]:
        print(result["blocked_reason"], file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
