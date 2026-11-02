# MCP Server Integrations

External MCP servers that enhance pentest capabilities when available.

## Bounty Platform MCPs

### HackerOne MCP
- Fetch program scope, policy, and response SLA
- Submit findings directly
- Check for duplicates before submission
- Track finding status

### Bugcrowd MCP
- Similar to HackerOne: scope, policy, submission
- Program brief parsing
- Reward range lookup

### Intigriti MCP
- European platform integration
- Scope and program details

## Knowledge Base MCPs

### Writeup Search MCP
- Search published vulnerability writeups by vuln class + tech stack
- Get real-world examples of exploitation chains
- Find bypass techniques for specific WAFs/frameworks
- Sources: HackerOne disclosed reports, blog posts, CTF writeups

### CVE Search MCP
- Query CVE database by product + version
- Get exploit availability (ExploitDB, Metasploit)
- Check EPSS score for likelihood of exploitation

## Reconnaissance MCPs

### Shodan MCP
- Query Shodan for target infrastructure
- Get exposed services, SSL certificates, tech stack
- Historical data for target

### Censys MCP
- Alternative to Shodan with certificate-focused search
- Find subdomains via certificate transparency

### SecurityTrails MCP
- DNS history, subdomain enumeration
- Whois history and associated domains

## How to Use

These MCPs are optional. The plugin works without them. When available:

1. **Scope phase**: Use bounty platform MCP to fetch official scope
2. **Recon phase**: Use Shodan/Censys/SecurityTrails for infrastructure intel
3. **Hunt phase**: Use writeup search for known techniques against identified stack
4. **Report phase**: Use bounty platform MCP for submission

## Configuration

MCP servers are configured outside the plugin. The plugin detects available
MCPs at engagement start and includes them in the Brain's available_tools.

To check available MCPs:
```
/quarry:status  → shows connected MCP servers
```

## Note on Privacy

- Never send target data to MCPs without operator confirmation
- Bounty platform MCPs may log queries — operator should be aware
- Shodan/Censys queries are visible to those platforms
