---
name: chain-ssrf-to-cloud
description: >
  Analyze and validate the SSRF-to-cloud-compromise chain: confirmed SSRF
  reaching cloud instance metadata services, extraction of IAM
  credentials/tokens from that metadata, and use of those credentials to
  access real cloud resources (storage, secrets manager, other instances).
  Use when chain-analysis or capability-map flags an SSRF-capable
  component running in a cloud environment (AWS/Azure/GCP/other).
  Do NOT use for SSRF reaching only other internal web services with no
  cloud metadata exposure — that's chain-web-to-rce or chain-custom
  territory depending on what's actually reached.
metadata:
  type: chain
  phase: chaining
  tools: [curl, aws_cli, az_cli, gcloud, burp]
depends_on: [chain-analysis, capability-map, trust-map]
feeds_into: [finding-validation, report-writing]
chains_with: [chain-web-to-rce, chain-info-to-exploit]
---

## Signals

- capability-map flagged a component with outbound-request capability running in a
  confirmed or likely cloud environment (CNAMEs, TLS cert SANs, response headers indicating
  AWS/Azure/GCP).
- An SSRF finding is already confirmed (server fetches an attacker-influenced URL) and the
  deployment target is cloud-hosted.
- A webhook, URL-preview, PDF-render, or image-fetch feature is reachable and its outbound
  destination isn't restricted to an external allow-list.

## Prerequisites

- SSRF reachability already confirmed per Gate 2 (can the vuln state exist and be reached) —
  this skill is for developing an already-reachable SSRF into a cloud-credential chain, not
  for discovering SSRF from scratch.
- Explicit scope confirmation that the cloud account in question belongs to the client and
  is in scope — metadata endpoints for a shared/multi-tenant hosting provider's *own*
  infrastructure are not in scope just because the target happens to run on them.

## Methodology

1. **Confirm the cloud provider and metadata endpoint.** AWS: `169.254.169.254` (IMDSv1/
   IMDSv2), Azure: `169.254.169.254` with `Metadata: true` header, GCP:
   `metadata.google.internal` with `Metadata-Flavor: Google`. Confirm which applies from
   asset-map/trust-map evidence (headers, CNAMEs) before guessing — probing the wrong
   provider's endpoint wastes budget and adds noise.

2. **Reach the metadata endpoint via the SSRF.** Supply the metadata address as the SSRF
   target. If the SSRF validates/filters the host, test standard bypasses relevant to that
   specific filter implementation (redirect-based reach-through, alternate IP encodings,
   DNS rebinding) — but only the ones that make sense given how the filter actually behaves;
   don't shotgun every known SSRF-filter-bypass technique against a filter you haven't
   characterized.

3. **Handle IMDSv2 (AWS) token requirement if present.** IMDSv2 requires a `PUT` request to
   obtain a session token before `GET`-ing credentials, which normal GET-based SSRF often
   cannot replicate — confirm whether the vulnerable component's HTTP client can be coerced
   into issuing the required PUT (some SSRF primitives, e.g. those going through a URL-
   fetching library, support method/header control; others don't). If IMDSv2-only and the
   primitive can't do PUT+headers, document this as a mitigating factor, not a dead end to
   hide — it meaningfully reduces real-world exploitability and that matters for CVSS/impact
   accuracy.

4. **Extract and scope the retrieved credentials.** From the metadata response, extract the
   IAM role name and temporary credentials (AccessKeyId/SecretAccessKey/Token for AWS,
   equivalent for Azure/GCP). Do not log full secret material in the report text — reference
   that credentials were obtained and store the raw evidence in the engagement's secured
   evidence store, redacted in any shared document.

5. **Demonstrate (minimally) what the credentials grant.** Using the extracted credentials,
   make the smallest possible read-only call that proves identity and scope (e.g.
   `aws sts get-caller-identity`, then one scoped, non-destructive, read-only call like
   listing — not downloading — one bucket/resource the role has access to). This is the
   Gate 4 (Impact) evidence: it proves material access to a cloud resource, not just
   credential extraction.

6. **Map the blast radius without exploiting it fully.** From the role's apparent
   permissions (via a safe enumeration call like `iam get-role-policy`/`simulate-principal-
   policy` if permitted, or by what you can observe), describe what the role *could* access
   — storage buckets, secrets manager entries, other instances, the ability to assume further
   roles — as Inferred impact, clearly separated from the Demonstrated minimal read you
   actually performed.

## Validation gate

- "SSRF" and "cloud credential extraction" and "cloud resource access" are three separate
  claims; each needs its own evidence. Do not report "SSRF leads to full cloud compromise"
  unless step 5's minimal resource access was actually demonstrated.
- Any further action beyond the minimal read-only proof call (listing additional resources,
  reading sensitive data, modifying anything) requires explicit operator sign-off per project
  human gates — the chain being "clearly severe" does not substitute for that confirmation.
- Credential material itself is never pasted into chat history, shared documents, or report
  drafts in full — reference its existence and scope, redact the values.

## Gotchas

- Many modern cloud deployments enforce IMDSv2-only and/or metadata hop-limit restrictions
  specifically to blunt this chain — a blocked attempt at step 3 is a real, reportable
  mitigating control, not evidence you did something wrong.
- A role's attached policy might look permissive in a static read but be further restricted
  by an IAM permissions boundary or SCP — don't claim broader access than what you actually
  demonstrated reaching.
- Containerized workloads (ECS/EKS/GKE) have their own metadata-credential layering (task
  roles vs instance roles) — confirm which layer you actually reached before describing the
  blast radius, instance-role access and task-role access are not the same thing.
- Temporary credentials from instance metadata typically expire within hours — note the
  extraction timestamp precisely since the PoC's reproducibility window is limited.
- If the SSRF-capable service turns out to run outside the cloud account you assumed (e.g. a
  third-party SaaS embed), stop — this is now a different scope question, raise it rather
  than continuing to extract that provider's credentials.
