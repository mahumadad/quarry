# Version Probes Catalog

> Read-only probes that detect exact software versions without payloads.
> Used to reduce false positives in CVE correlation — a version match
> moves the finding from "banner says X" to "probe confirms X".
>
> Based on CVEngine's version probe model.

## Contract

- All probes are **GET-only** or passive (banner grab, TLS handshake).
- No authentication required (probes against authenticated endpoints go
  in the engagement-specific validation plan, not here).
- Each probe returns a version string or "unknown".
- Backport awareness: a version match alone is not proof of
  vulnerability — check distro-specific trackers (see cvss4-epss-kev.md,
  Backport awareness section).

## Probe Catalog

### Web Servers

| Product | Probe | Where | Version extracted from |
|---------|-------|-------|----------------------|
| Apache httpd | `curl -sI {target}` | Any page | `Server: Apache/2.4.52` header |
| Nginx | `curl -sI {target}` | Any page | `Server: nginx/1.24.0` header |
| IIS | `curl -sI {target}` | Any page | `Server: Microsoft-IIS/10.0` header |
| LiteSpeed | `curl -sI {target}` | Any page | `Server: LiteSpeed` header |
| Caddy | `curl -sI {target}` | Any page | `Server: Caddy` header |

### Application Frameworks

| Product | Probe | Where | Version extracted from |
|---------|-------|-------|----------------------|
| Rails | `curl -s {target}` | Any page | `X-Powered-By` header, or `/rails/info/properties` if debug enabled |
| Django | `curl -sI {target}/admin/` | Admin login | `X-Frame-Options` + Django-specific HTML patterns |
| Laravel | `curl -s {target}` | Error page | Ignition/Whoops version in stack trace |
| Spring Boot | `curl -s {target}/actuator/info` | Actuator | `build.version` in JSON response |
| Express | `curl -sI {target}` | Any page | `X-Powered-By: Express` header (no version, but confirms framework) |
| Next.js | `curl -s {target}/_next/static/chunks/` | Build manifest | `buildId` in `__NEXT_DATA__` JSON |
| FastAPI | `curl -s {target}/openapi.json` | OpenAPI spec | `info.version` field in JSON |
| ASP.NET | `curl -sI {target}` | Any page | `X-Powered-By: ASP.NET`, `X-AspNet-Version` headers |

### Databases (banner grab)

| Product | Probe | Where | Version extracted from |
|---------|-------|-------|----------------------|
| MySQL/MariaDB | `nmap -sV -p 3306 {host}` | TCP banner | Version string in handshake |
| PostgreSQL | `nmap -sV -p 5432 {host}` | TCP banner | Version in startup message |
| MongoDB | `nmap -sV -p 27017 {host}` | TCP banner | `isMaster` response (if auth not required) |
| Redis | `nmap -sV -p 6379 {host}` | TCP banner | `redis_version` in `INFO` response |
| Elasticsearch | `curl -s {host}:9200` | HTTP root | `version.number` in JSON |

### CMS / E-commerce

| Product | Probe | Where | Version extracted from |
|---------|-------|-------|----------------------|
| WordPress | `curl -s {target}/wp-login.php` | Login page | `?ver=X.Y.Z` in CSS/JS URLs, `<meta name="generator">` |
| Magento | `curl -s {target}/magento_version` | Version endpoint | Plain text version (if not disabled) |
| Drupal | `curl -s {target}/CHANGELOG.txt` | Changelog | First version entry |
| Joomla | `curl -s {target}/administrator/manifests/files/joomla.xml` | Manifest | `<version>` XML tag |

### Network / Infrastructure

| Product | Probe | Where | Version extracted from |
|---------|-------|-------|----------------------|
| OpenSSH | `nmap -sV -p 22 {host}` | SSH banner | `SSH-2.0-OpenSSH_8.9p1` |
| Postfix | `nmap -sV -p 25 {host}` | SMTP banner | `220 mail.example.com ESMTP Postfix` |
| Dovecot | `nmap -sV -p 143 {host}` | IMAP banner | `* OK [CAPABILITY ...] Dovecot ready.` |
| HAProxy | `curl -sI {target}` | Any page | Custom `Via` or stats page |
| Varnish | `curl -sI {target}` | Any page | `Via: 1.1 varnish (Varnish/7.x)`, `X-Varnish` |

### Firewalls / VPN (passive)

| Product | Probe | Where | Version extracted from |
|---------|-------|-------|----------------------|
| FortiGate | `curl -sk https://{host}/login` | Login page | `fortios-version` in JS/HTML, `X-Frame-Options` pattern |
| Palo Alto PAN-OS | `curl -sk https://{host}` | Login page | Version in login page HTML (`pan-os-version`) |
| Cisco ASA | `nmap -sV -p 443 {host}` | TLS cert | `CN=` in certificate, ASDM version in HTML |
| SonicWall | `curl -sk https://{host}` | Login page | Version in page title or JS |

### TLS / Certificate

| Attribute | Probe | Extracted from |
|-----------|-------|---------------|
| Certificate chain | `openssl s_client -connect {host}:443` | Full chain PEM |
| Cipher suites | `nmap --script ssl-enum-ciphers -p 443 {host}` | Supported ciphers by protocol |
| Protocol versions | `nmap --script ssl-enum-ciphers -p 443 {host}` | TLSv1.0/1.1/1.2/1.3 support |
| JARM fingerprint | `jarm {host}` | JARM hash (identifies server-side TLS stack) |

## Usage in the Plugin

1. **Recon phase**: `recon_pipeline.py` runs applicable probes during
   tech fingerprinting to populate `AppProfile.detected_versions`.
2. **CVE correlation**: `engine/priority.py` uses version match as a
   Smoke signal (`version_match: true`).
3. **Validation**: `engine/validation.py` uses VERSION_PROBE checks to
   confirm CVE-based findings.
4. **Backport check**: before promoting a version-match finding to
   Demonstrated, check distro trackers (OSV, Debian, RHEL).

## Adding New Probes

Add to this catalog when you encounter a product without version
detection. Requirements:
- Must be read-only (GET, banner grab, or passive TLS)
- Must extract a parseable version string
- Must note where backports could cause false positives
- Test against a real instance before adding
