# KWALL Production Deployment & Operations Guide

This guide covers installing and operating KWALL in Kubernetes environments (EKS, GKE, AKS, OpenShift, Bare-Metal, and KinD).

---

## 1. Prerequisites

### Kernel Requirements
* **Linux Kernel**: 5.15+ (Kernel 6.1+ recommended for enhanced BPF ring-buffers).
* **BPF Type Format (BTF)**: Kernel compiled with `CONFIG_DEBUG_INFO_BTF=y`.
* **BPF LSM**: Kernel compiled with `CONFIG_BPF_LSM=y`. Verify via:
  ```bash
  cat /sys/kernel/security/lsm
  # Ensure 'bpf' is present in output (e.g., capability,yama,bpf,apparmor)
  ```
* **Kernel Mounts**:
  * `/sys/kernel/btf`
  * `/sys/fs/bpf` (BPF filesystem mounted with `mount -t bpf bpf /sys/fs/bpf`)
  * `/sys/fs/cgroup` (`cgroup2` unified hierarchy)

---

## 2. Installation via Helm

### Quick Install with Kubernetes Gateway API
```bash
# Add KWALL Helm repository (or use local path)
helm repo add kwall https://charts.kwall.io
helm repo update

# Deploy KWALL with Gateway API and Web Dashboard enabled
helm upgrade --install kwall deployments/helm/kwall \
  --namespace kwall-system \
  --create-namespace \
  --set api.enabled=true \
  --set dashboard.enabled=true \
  --set gatewayApi.enabled=true \
  --set gatewayApi.gatewayClassName=cilium
```

### Verification
```bash
# Verify DaemonSet agent rollout
kubectl rollout status daemonset/kwall-agent -n kwall-system

# Verify Operator and API pods
kubectl get pods -n kwall-system -l app.kubernetes.io/part-of=kwall

# Check Gateway and HTTPRoute status
kubectl get gateway,httproute -n kwall-system
```

---

## 3. Local Development with KinD

A pre-configured KinD cluster setup is provided under `deployments/kind/`:

```bash
# Create KinD cluster with host BPF and cgroup mounts enabled
kind create cluster --config deployments/kind/kind-config.yaml --name kwall-dev

# Apply KWALL Custom Resource Definitions (CRDs)
kubectl apply -f deployments/crds/

# Install KWALL Helm chart
helm install kwall deployments/helm/kwall -n kwall-system --create-namespace
```

---

## 4. Operating via KWALL CLI (`kwall`)

Build the CLI binary:
```bash
cargo build --release -p kwall-cli
sudo cp target/release/kwall /usr/local/bin/
```

### Inspect Attached Probes
```bash
kwall probe status
# Output shows attached XDP, TC, LSM, and tracepoint programs on interfaces
```

### Validate a Security Policy
```bash
kwall policy validate -f policy.yaml
# Validates schema and eBPF BPF_PROG_LOAD compatibility
```

### Stream Live Security Events
```bash
kwall events tail --follow --severity HIGH,CRITICAL
```

### Isolate / Quarantine a Compromised Pod
```bash
kwall pod quarantine --namespace production --pod payment-service-7f89d-4kx2b
```
