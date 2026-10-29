# Tool Fallback Map

> When a primary tool is unavailable or fails, use these alternatives.
> Integrated with `engine/tool_registry.py` TOOL_FALLBACKS dict.
> All fallbacks must be scope-safe and read-only where the primary is.

## Capability → Tool Chain

| Capability | Primary | Fallback 1 | Fallback 2 | Notes |
|-----------|---------|-----------|-----------|-------|
| **Port scan** | nmap | rustscan | masscan | rustscan wraps nmap for speed; masscan is SYN-only |
| **Service fingerprint** | nmap -sV | — | — | No real alternative for service detection |
| **Content discovery** | ffuf | feroxbuster | gobuster | feroxbuster has recursion built-in |
| **HTTP fuzzing** | ffuf | wfuzz | — | wfuzz older but stable |
| **Template scanning** | nuclei | nikto | — | nikto less precise, more noise |
| **SQL injection** | sqlmap | ghauri | — | ghauri is Python-native, fewer deps |
| **NoSQL injection** | nosqlmap | — | — | Manual testing via curl as fallback |
| **Subdomain discovery** | subfinder | amass | assetfinder | amass is slower but deeper |
| **DNS resolution** | dig | nslookup | host | dig has most options |
| **HTTP probing** | httpx | curl | httprobe | curl always available; httprobe just alive check |
| **Web crawling** | katana | gospider | hakrawler | katana supports headless JS |
| **JS analysis** | linkfinder | subjs | katana -jc | Different approaches: regex vs crawl |
| **Secret scanning** | gitleaks | trufflehog | — | trufflehog does verified secrets |
| **Tech fingerprint** | whatweb | httpx -tech | wappalyzer-cli | httpx -tech is lightweight |
| **Screenshot** | gowitness | aquatone | eyewitness | gowitness is fastest |
| **OAST/OOB** | interactsh-client | — | Burp Collaborator | interactsh is self-hosted option |
| **URL history** | gau | waybackurls | — | Both hit Wayback; gau adds more sources |
| **Certificate info** | openssl s_client | nmap --script ssl-cert | sslyze | All provide cert chain |
| **TLS audit** | testssl.sh | nmap --script ssl-enum-ciphers | sslyze | testssl.sh most comprehensive |
| **Directory brute** | dirsearch | gobuster | dirb | dirsearch has smart wordlist |
| **GraphQL** | graphql-cop | — | curl (manual) | Manual introspection query via curl |
| **JWT testing** | jwt_tool | — | Manual (jwt.io decode + forge) | jwt_tool automates all attacks |
| **WordPress** | wpscan | — | nuclei -t wordpress/ | wpscan has vuln DB; nuclei has templates |

## Universal Fallback: curl

`curl` is the universal fallback for any HTTP-based tool. When all
specific tools fail, construct the equivalent request manually:

```bash
# Content discovery
curl -s -o /dev/null -w '%{http_code}' "{target}/{path}"

# Header grab
curl -sI "{target}"

# POST with payload
curl -s -X POST -H 'Content-Type: application/json' -d '{}' "{target}"

# Follow redirects
curl -sL -o /dev/null -w '%{url_effective}' "{target}"
```

## Integration

The `TOOL_FALLBACKS` dict in `engine/tool_registry.py` uses this map
to auto-select available alternatives when `ToolRegistry.select()`
finds the primary unavailable.
