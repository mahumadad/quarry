---
name: cloud-recon
description: >
  Enumerate cloud storage and metadata exposure: AWS S3 buckets, Azure blob storage, GCP
  storage buckets, and cloud instance metadata endpoints (SSRF-adjacent). Use after
  subdomain-discovery/osint surface naming patterns that suggest cloud usage, to find
  misconfigured public storage and metadata-service exposure. Do NOT use for general web
  app testing on cloud-hosted apps — that's web-crawling/api-discovery; this skill is
  specifically about cloud-provider storage and metadata services.
metadata:
  type: recon
  phase: recon
  tools: [aws-cli, cloud_enum, s3scanner, gcpbucketbrute, curl]
depends_on: [subdomain-discovery, osint]
feeds_into: []
---

## Signals

- Subdomain/JS/OSINT recon surfaced names suggesting cloud storage buckets (`*-assets`,
  `*-backup`, `*-static`, company name patterns common for S3/blob naming).
- The target app is confirmed to run on AWS/Azure/GCP (from `tech-stack-fingerprint` or
  cert/CNAME evidence) and SSRF or server-side request behavior is present, raising
  metadata-endpoint exposure risk.

## Prerequisites

- Org/brand name variants and any discovered bucket-shaped hostnames from
  `subdomain-discovery`/`osint`/`js-analysis`.

## Methodology

1. Generate candidate bucket names from the org name, product names, and known naming
   conventions (`<org>`, `<org>-prod`, `<org>-backup`, `<org>-assets`, `<org>-static`, etc.):
   ```bash
   cloud_enum -k example -k examplecorp -k example-prod -k example-backup --disable-azure --disable-gcp
   ```
2. S3-specific bucket enumeration and permission check:
   ```bash
   s3scanner scan --bucket-file candidate-buckets.txt
   aws s3 ls s3://example-backup --no-sign-request          # anonymous access check
   aws s3 ls s3://example-backup --no-sign-request --recursive | head    # listable contents
   ```
   A bucket that allows anonymous `ListBucket`/`GetObject` is a confirmed finding — capture
   the exact `aws s3 ls` output and, for GetObject, a redacted sample of what's retrievable.
3. Azure Blob Storage enumeration (naming convention: `<account>.blob.core.windows.net`):
   ```bash
   cloud_enum -k example -k examplecorp --disable-aws --disable-gcp
   curl -s "https://examplestorage.blob.core.windows.net/backup?restype=container&comp=list"
   ```
4. GCP Storage bucket enumeration:
   ```bash
   gcpbucketbrute -k example -u                               # -u checks ACLs, not just existence
   curl -s "https://storage.googleapis.com/example-backup/"
   gsutil ls gs://example-backup                              # anonymous listing attempt
   ```
5. Cloud metadata endpoint exposure — relevant wherever the app makes server-side requests
   on the target's behalf (confirm via SSRF-prone features: URL preview, webhook callbacks,
   PDF/image generation from a URL, etc.). Only test this against the target's own
   server-side request functionality, never by directly hitting a metadata IP you don't
   control:
   ```bash
   # AWS IMDSv1 (if the app is vulnerable to SSRF and can be coerced to fetch this)
   curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
   # IMDSv2 requires a token first — absence of IMDSv2 enforcement is itself a finding
   curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
   # GCP metadata
   curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"
   # Azure metadata
   curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
   ```
6. For any accessible bucket/blob, enumerate contents shallowly to assess sensitivity
   without exfiltrating beyond what's needed for proof:
   ```bash
   aws s3 ls s3://example-backup --no-sign-request --recursive | head -50
   ```

## Tooling

`cloud_enum` (multi-cloud bucket brute force), `s3scanner`, `aws s3 ls --no-sign-request`,
`gsutil ls`, `gcpbucketbrute`, `curl` against provider metadata IPs/hostnames.

## Validation gate

- [ ] Any bucket/blob confirmed accessible has exact command + output saved as evidence,
      with contents sampled (not fully exfiltrated) per `opsec-discipline`'s data-handling rule.
- [ ] Metadata-endpoint testing only performed through the target's own server-side request
      functionality (confirmed SSRF vector), never by scanning random IPs hoping to land on
      someone else's cloud instance metadata — that would be out of scope and potentially
      hitting infrastructure outside the engagement entirely.
- [ ] Bucket ownership confirmed to belong to the client (not a similarly-named third party)
      before treating it as in-scope.

## Gotchas

- Bucket naming brute force returns a lot of noise — many `<common-word>-backup` style
  names exist for unrelated companies; confirm actual ownership (bucket contents referencing
  the client, or DNS evidence) before reporting.
- IMDSv1 exposure is a real, well-known SSRF escalation path but only matters if there's an
  actual SSRF primitive in the app to reach it through — don't report metadata-endpoint
  "exposure" from a network you directly control as if it were discovered on the target.
- Exfiltrating full bucket contents "to be thorough" violates both `opsec-discipline`'s
  data-handling rule and most RoEs' data-minimization requirements — a directory listing
  and a small representative sample is sufficient proof.
- Public read access on a bucket that only contains intentionally public static assets
  (CSS, images, public marketing PDFs) is not automatically a finding — assess actual
  content sensitivity before escalating.
