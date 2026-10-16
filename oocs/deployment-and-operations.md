# Deployment & Operations Guide

This guide covers building, packaging, deploying, and operating KWALL in Kubernetes environments.

---

## Deployment Architecture

KWALL deploys via Helm as two primary workloads:
1. **`kwall-controller` (Deployment, 2 Replicas with leader election)**:
   - Watches CRDs and computes cluster-wide security policies.
   - Allocates unique numeric identities for workload label sets.
2. **`kwall-agent` (DaemonSet, 1 Pod per Node)**:
   - Runs with `hostNetwork: true`, `privileged: true`, and access to `/sys/fs/bpf` and `/sys/kernel/btf`.
   - Loads eBPF programs, configures netkit devices, and handles packet filtering.
   - Installs the `kwall-cni` binary into `/opt/cni/bin/`.

---

## Helm Chart Deployment

KWALL includes a production-ready Helm chart located at `deploy/helm/kwall`.

### Prerequisites
- Kubernetes cluster >= 1.28
- Linux nodes running kernel >= 6.8 with eBPF, BTF, and netkit enabled
- Helm 3.x installed

### Quick Installation

```bash
# Install KWALL into kube-system or custom namespace
helm install kwall deploy/helm/kwall \
  --namespace kwall-system \
  --create-namespace \
  --set agent.image.tag="v0.1.0" \
  --set controller.image.tag="v0.1.0"
```

### Values Customization (`values.yaml`)

```yaml
controller:
  replicas: 2
  image:
    repository: ghcr.io/kwall-io/kwall-controller
    tag: latest
    pullPolicy: IfNotPresent
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 100m
      memory: 128Mi

agent:
  image:
    repository: ghcr.io/kwall-io/kwall-agent
    tag: latest
    pullPolicy: IfNotPresent
  hostNetwork: true
  privileged: true
  bpfFsPath: "/sys/fs/bpf"
  cniBinDir: "/opt/cni/bin"
  cniConfDir: "/etc/cni/net.d"
  resources:
    limits:
      cpu: 2000m
      memory: 2Gi
    requests:
      cpu: 200m
      memory: 256Mi

observability:
  prometheus:
    enabled: true
    port: 9090
  loki:
    enabled: true
    endpoint: "http://loki.observability.svc:3100"
  opentelemetry:
    enabled: true
    endpoint: "otel-collector.observability.svc:4317"
```

---

## Building from Source

### Prerequisites
- **Rust Toolchain**: `rustup default 1.99.0` (or latest stable)
- **Nightly Rust**: `rustup toolchain install nightly --component rust-src` (for compiling Aya eBPF targets)
- **Host Tools**: `clang`, `llvm`, `libelf-dev`, `pkg-config`, `make`

### Makefile Recipes

The root `Makefile` provides standardized targets for all operations:

```bash
# Check formatting, linting, and audit dependencies
make check

# Build userspace Rust binaries in release mode
make build

# Build eBPF programs for bpfel-unknown-none target
make ebpf

# Run unit and integration tests across the workspace
make test

# Build production multi-stage container images
make docker-build

# Generate and apply CRDs into local Kubernetes cluster
make crd-install

# Deploy KWALL via Helm
make helm-deploy
```

---

## Operational Health & Troubleshooting

### 1. Check Agent Pod Logs
```bash
kubectl logs -n kwall-system -l app.kubernetes.io/name=kwall-agent --tail=100 -f
```

### 2. Verify Pinned BPF Maps
Log into a node or agent container and verify the BPF mount point:
```bash
ls -la /sys/fs/bpf/kwall/
# Expected:
# - kwall_conntrack
# - kwall_policy_ingress
# - kwall_policy_egress
# - kwall_events
# - kwall_metrics
```

### 3. Check CNI Plugin Status
Verify that `kwall-cni` was placed in `/opt/cni/bin`:
```bash
ls -la /opt/cni/bin/kwall-cni
cat /etc/cni/net.d/10-kwall.conflist
```

### 4. Running Node Diagnostics
Run `kwall-cli` inside the agent container:
```bash
kubectl exec -it -n kwall-system daemonset/kwall-agent -- kwall status
```
