# Headless Mode & CI Integration

> Running the pentest plugin in non-interactive mode for CI/CD pipelines.
> Integrates with existing `workflows/pr-scan.yaml` and `workflows/ci-scan.yaml`.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Clean — no findings above threshold |
| 1 | Findings — at least one finding above severity threshold |
| 2 | Error — scan failed, scope missing, or tool unavailable |
| 3 | Timeout — scan exceeded time limit |

## Flags

```
--headless          Run without operator interaction (all gates auto-skip)
--threshold LEVEL   Minimum severity to trigger exit code 1 (critical|high|medium|low|info)
--output-format FMT Output format: json (default), markdown, sarif
--output FILE       Write results to file (default: stdout)
--scope FILE        Path to scope definition file
--timeout SECONDS   Maximum scan duration (default: 3600)
--budget CALLS      Maximum tool calls (default: 200)
--phases PHASES     Comma-separated phases to run (recon,hunt,chain,validate)
--diff-only         Only scan files/endpoints changed in current PR
--base-ref REF      Base git ref for --diff-only (default: main)
```

## GitHub Actions Example

```yaml
name: Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  pentest-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed for --diff-only

      - name: Run pentest scan
        run: |
          claude --headless --skill pentest \
            --scope .pentest-scope.json \
            --threshold high \
            --diff-only \
            --base-ref origin/main \
            --output-format sarif \
            --output results.sarif \
            --timeout 1800 \
            --budget 100

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Scope File Format

```json
{
  "target": "https://staging.example.com",
  "assets": ["staging.example.com"],
  "phases": ["recon", "hunt"],
  "vuln_classes": ["sqli", "xss", "ssrf", "idor", "auth-bypass"],
  "exclusions": ["/admin/*", "/api/internal/*"],
  "auth": {
    "type": "bearer",
    "token_env": "PENTEST_AUTH_TOKEN"
  }
}
```

## Integration with Existing Workflows

### pr-scan.yaml

The existing `workflows/pr-scan.yaml` runs on pull requests. In headless
mode, it uses `--diff-only` to narrow scope to changed files via
`engine/target_diff.py:diff_scope_from_git()`.

### ci-scan.yaml

The existing `workflows/ci-scan.yaml` runs on schedule or manual trigger.
Full scope scan without `--diff-only`, typically on staging environments.

## SARIF Output

When `--output-format sarif` is used, findings map to SARIF as:
- `result.ruleId` → finding vuln_class
- `result.level` → severity (error=critical/high, warning=medium, note=low/info)
- `result.message` → finding title + description
- `result.locations` → target_asset + endpoint
- `result.properties` → evidence_tag, cvss_score, mitre_attack

## Limitations in Headless Mode

- All operator gates are skipped (exploitation, destructive actions)
- Seven-question gate auto-fails (no exploitation in CI)
- OAST callbacks require network access to interactsh
- Browser-based verification is skipped
- Findings cap at Confirmed status (no Exploited/Chained)
