---
name: credential-hygiene
description: Revoke, rotate, or securely destroy all credentials obtained or created during the engagement
domain: core
depends_on: [scope-discipline]
---

# Credential Hygiene

Ensure no operator-held credentials survive past engagement closeout.

## Checklist

1. **Inventory** — List all credentials obtained or created: test accounts,
   API keys, tokens, session cookies, SSH keys, certificates.

2. **Test accounts** — Request client to disable/delete, or delete directly
   if operator has admin access. Confirm deletion.

3. **Captured tokens** — Rotate or invalidate any tokens the operator
   extracted (JWT secrets, API keys). If the operator cannot rotate them,
   notify the client with the specific credentials that need rotation.

4. **Local copies** — Purge plaintext credentials from the workspace.
   The custody log retains hashed references, not the values.

5. **Password manager** — Remove any target entries from operator's
   password manager or browser saved passwords.

## Rules

- Never retain plaintext credentials after closeout.
- Log each credential disposal action in the custody chain.
- If a credential cannot be revoked (e.g., leaked database password),
  document it as a critical remediation item.
