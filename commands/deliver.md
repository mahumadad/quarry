---
name: quarry:deliver
description: Package and deliver engagement artifacts with optional GPG encryption
argument-hint: "<deliverable_dir> [--gpg RECIPIENT | --gpg-symmetric]"
allowed-tools: Bash(*), Read(*), Write(*), Edit(*)
---

# /quarry:deliver — Package and deliver engagement artifacts

Usage: `/quarry:deliver <deliverable_dir> [--gpg RECIPIENT | --gpg-symmetric]`

## What it does

1. Builds the SHA-256 manifest of ALL deliverable files
   (report, findings, evidence, exports, custody log) via
   `engine/deliver.py` → `manifest.json`.
2. Verifies the custody log one last time (must be INTACT before
   packaging — if broken, DO NOT deliver: investigate first).
3. Generates the `.tar.gz` bundle with the manifest inside.
4. Optional encryption with gpg (by recipient or symmetric AES256) per the
   delivery channel agreed with the client.
5. Records the packaging in custody (bundle hash included).

## Rules

- The manifest is the guarantee: the client can re-verify any file
  against it. If anything differs post-delivery, the manifest resolves
  who altered what.
- The unencrypted bundle NEVER goes through non-agreed channels (generic
  corporate email, public links).
- Store the delivered bundle hash in custody — if the client reports
  "the file won't open" or disputes content, the hash settles it.
- Delivery = custody event with date, channel, and recipient.

## Examples

```
/quarry:deliver outputs/acme-2026-09/deliverable --gpg security@acme.com
/quarry:deliver outputs/acme-2026-09/deliverable --gpg-symmetric
```
