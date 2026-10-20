"""PreToolUse guard for Bash commands.

Validates that commands target in-scope assets and aren't destructive
without prior human approval. Called by hooks/hooks.json on every Bash call.

Usage: python3 guard.py --command "nmap -sV target.com"
"""

import argparse
import json
import sys
from pathlib import Path

DESTRUCTIVE_PATTERNS = [
    "rm -rf", "rm -r", "rmdir",
    "DROP TABLE", "DROP DATABASE", "DELETE FROM", "TRUNCATE",
    "mkfs", "dd if=", "format",
    "> /dev/", "chmod 777",
    "iptables -F", "iptables --flush",
]

DANGEROUS_TOOLS = [
    "msfconsole", "msfvenom", "exploit/",
    "hydra", "hashcat", "john",
    "responder", "impacket-",
    "sqlmap --os-shell", "sqlmap --os-cmd",
]

BLOCKED_ALWAYS = [
    "shutdown", "reboot", "halt", "poweroff",
    "init 0", "init 6",
]


def check_command(command: str, scope_file: str | None = None) -> dict:
    result = {"allowed": True, "warnings": [], "blocked_reason": None}

    cmd_lower = command.lower().strip()

    for pattern in BLOCKED_ALWAYS:
        if pattern in cmd_lower:
            result["allowed"] = False
            result["blocked_reason"] = f"Blocked: '{pattern}' is never allowed"
            return result

    for pattern in DESTRUCTIVE_PATTERNS:
        if pattern.lower() in cmd_lower:
            result["warnings"].append(
                f"DESTRUCTIVE: command contains '{pattern}'. "
                "Requires explicit human approval before execution."
            )

    for tool in DANGEROUS_TOOLS:
        if tool.lower() in cmd_lower:
            result["warnings"].append(
                f"DANGEROUS TOOL: '{tool}' detected. "
                "Verify scope and get human approval before exploitation."
            )

    if scope_file:
        scope_path = Path(scope_file)
        if scope_path.exists():
            try:
                from scope import Scope
                scope = Scope.load(scope_path)
                valid, reason = scope.validate_command(command)
                if not valid:
                    result["allowed"] = False
                    result["blocked_reason"] = f"OUT OF SCOPE: {reason}"
            except Exception:
                pass

    return result


def main():
    parser = argparse.ArgumentParser(description="Pentest command guard")
    parser.add_argument("--command", required=True, help="Command to validate")
    parser.add_argument("--scope-file", help="Path to scope.json")
    args = parser.parse_args()

    result = check_command(args.command, args.scope_file)
    print(json.dumps(result))

    if not result["allowed"]:
        sys.exit(1)
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"⚠ {w}", file=sys.stderr)


if __name__ == "__main__":
    main()
