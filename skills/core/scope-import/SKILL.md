---
name: scope-import
description: >
  Import engagement scope from structured sources: bounty platform JSON,
  Burp project files, or YAML/TOML config.
metadata:
  category: core
  phase: [INIT, SCOPED]
  priority: P0
  depends_on: [scope-discipline]
  feeds_into: [engagement-flow, recon/*]
  chains_with: []
---

# Scope Import

Import and validate engagement scope from external sources instead of
manual `/pt:scope` entry.

## Supported Formats

### 1. HackerOne JSON (program policy export)
```json
{
  "targets": {
    "in_scope": [
      {"asset_identifier": "*.example.com", "asset_type": "URL"},
      {"asset_identifier": "api.example.com", "asset_type": "URL"}
    ],
    "out_of_scope": [
      {"asset_identifier": "blog.example.com", "asset_type": "URL"}
    ]
  }
}
```

### 2. Bugcrowd Scope
```json
{
  "target_groups": [
    {
      "in_scope": true,
      "targets": [{"name": "*.example.com", "uri": "https://example.com"}]
    }
  ]
}
```

### 3. YAML Config
```yaml
engagement:
  name: "Example Corp Pentest"
  type: pentest  # bounty | pentest | comprehensive
  client: "Example Corp"
  
scope:
  in_scope:
    - "*.example.com"
    - "api.example.com"
    - "192.168.1.0/24"
  out_of_scope:
    - "blog.example.com"
    - "*.wordpress.com"
  
  rules:
    - "No DoS testing"
    - "No social engineering"
    - "Testing hours: 9am-6pm EST"
  
credentials:
  - name: "test_user"
    type: "password"
    username: "testuser@example.com"
    value: "TestPass123!"
    scope: "authenticated user access"
  - name: "admin_user"
    type: "password"
    username: "admin@example.com"
    value: "AdminPass456!"
    scope: "admin panel access"
```

### 4. Burp Project (XML export)
```
Extract target scope from Burp Suite project file:
- Target > Scope > Include/Exclude patterns
- Site map discovered hosts
```

## Import Protocol

1. **Read the source file** — detect format automatically
2. **Parse scope** — extract in-scope and out-of-scope assets
3. **Validate assets** — DNS resolution, reachability check
4. **Load into scope engine** — `engine/scope.py`
5. **Import credentials** if present → `engine/vault.py`
6. **Show summary** to operator for confirmation
7. **Set engagement mode** from config or ask operator

## Validation Gate

After import:
```
□ In-scope assets resolve? (DNS check)
□ Out-of-scope assets listed? (explicit exclusions)
□ Engagement type set? (bounty/pentest/comprehensive)
□ Operator confirmed scope is correct?
```

## Usage

```
/pt:scope-import path/to/scope.yaml
/pt:scope-import path/to/hackerone-policy.json
```

The command auto-detects format and imports accordingly.
