"""Headless mode for CI/CD integration.

Wraps engagement execution for non-interactive pipelines (GitHub Actions,
GitLab CI, etc.) with structured exit codes and SARIF-compatible output.

Exit codes:
  0 — clean (no findings above threshold)
  1 — findings above severity threshold
  2 — runtime error
  3 — scope not confirmed
"""

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

try:
    from .findings import FindingsStore, Finding
except ImportError:
    from findings import FindingsStore, Finding


EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_NO_SCOPE = 3

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class HeadlessConfig:
    audit_dir: str = "."
    severity_threshold: str = "medium"
    output_format: str = "sarif"
    output_file: str = ""
    scope_file: str = ""


class HeadlessRunner:
    def __init__(self, config: HeadlessConfig):
        self.config = config
        self.store = FindingsStore(config.audit_dir)

    def run(self) -> int:
        scope_path = Path(self.config.scope_file) if self.config.scope_file else None
        if scope_path and not scope_path.exists():
            self._err("Scope file not found — cannot run without confirmed scope.")
            return EXIT_NO_SCOPE

        state_dir = Path(self.config.audit_dir) / ".pentest-state"
        if not state_dir.exists():
            self._err("No .pentest-state found — run an engagement first.")
            return EXIT_ERROR

        self.store._load()
        findings = self.store.list_by_status()
        above = self._findings_above_threshold(findings)

        output = self.format_ci_output(findings)
        if self.config.output_file:
            Path(self.config.output_file).write_text(
                json.dumps(output, indent=2))

        if above:
            self._out(f"{len(above)} finding(s) at or above "
                      f"{self.config.severity_threshold} severity.")
            return EXIT_FINDINGS

        self._out(f"{len(findings)} finding(s), none above threshold.")
        return EXIT_CLEAN

    def _findings_above_threshold(self, findings: list[Finding]) -> list[Finding]:
        threshold = SEVERITY_ORDER.get(self.config.severity_threshold, 2)
        return [f for f in findings
                if SEVERITY_ORDER.get(f.severity, 0) >= threshold
                and f.status != "killed"]

    def format_ci_output(self, findings: list[Finding]) -> dict:
        """SARIF v2.1.0 compatible output for GitHub Code Scanning."""
        results = []
        for f in findings:
            if f.status == "killed":
                continue
            result = {
                "ruleId": f.vuln_class or f.id,
                "level": self._sarif_level(f.severity),
                "message": {"text": f.title or f.description or f.vuln_class},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target_asset or "unknown"},
                    },
                }],
                "properties": {
                    "finding_id": f.id,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "evidence_tag": f.evidence_tag,
                    "status": f.status,
                },
            }
            if f.cwe:
                result["taxa"] = [{"id": c, "toolComponent": {"name": "CWE"}}
                                  for c in f.cwe]
            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "quarry",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/mahumadad/quarry",
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                }],
            }],
        }

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}.get(severity, "none")

    @staticmethod
    def _out(msg: str):
        print(f"[pentest-ci] {msg}")

    @staticmethod
    def _err(msg: str):
        print(f"[pentest-ci] ERROR: {msg}", file=sys.stderr)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Pentest plugin — headless CI mode")
    parser.add_argument("--audit-dir", default=".")
    parser.add_argument("--severity-threshold", default="medium",
                        choices=list(SEVERITY_ORDER.keys()))
    parser.add_argument("--output", default="", help="Path for SARIF output file")
    parser.add_argument("--scope-file", default="")
    args = parser.parse_args()

    config = HeadlessConfig(
        audit_dir=args.audit_dir,
        severity_threshold=args.severity_threshold,
        output_file=args.output,
        scope_file=args.scope_file,
    )
    runner = HeadlessRunner(config)
    sys.exit(runner.run())


if __name__ == "__main__":
    main()
