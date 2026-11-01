#!/usr/bin/env bash
# ==============================================================================
# KWALL — Multi-Node Helm Deployment & DaemonSet Rollout Script
# ==============================================================================
set -euo pipefail

NAMESPACE="kwall-system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=================================================================="
echo "  KWALL: Deploying Operator & eBPF DaemonSet via Helm (3 Nodes)"
echo "=================================================================="

cd "${REPO_ROOT}"

# 1. Install or update Custom Resource Definitions (CRDs)
echo "[INFO] Applying KWALL Custom Resource Definitions..."
kubectl apply -f deployments/crds/kwall.io_networkpolicies.yaml
kubectl apply -f deployments/crds/kwall.io_runtimepolicies.yaml

# 2. Deploy KWALL Operator and DaemonSet via Helm using local images
echo "[INFO] Deploying Helm chart to namespace '${NAMESPACE}'..."
helm upgrade --install kwall ./deployments/helm/kwall \
    --namespace "${NAMESPACE}" \
    --create-namespace \
    --set agent.image.repository="kwall-agent" \
    --set agent.image.tag="latest" \
    --set agent.image.pullPolicy="Never" \
    --set operator.image.repository="kwall-operator" \
    --set operator.image.tag="latest" \
    --set operator.image.pullPolicy="Never"

# 3. Wait for Operator deployment rollout
echo "[INFO] Waiting for kwall-operator rollout in namespace '${NAMESPACE}'..."
kubectl rollout status deployment/kwall-operator -n "${NAMESPACE}" --timeout=120s

# 4. Wait for Agent DaemonSet rollout across all 3 nodes (1 control-plane, 2 workers)
echo "[INFO] Waiting for kwall-agent DaemonSet rollout across all 3 cluster nodes..."
kubectl rollout status daemonset/kwall-agent -n "${NAMESPACE}" --timeout=120s

# 5. Verify DaemonSet pods running on each node
echo "[INFO] Pods in '${NAMESPACE}' namespace:"
kubectl get pods -n "${NAMESPACE}" -o wide

# 6. Verify automated node labeling performed by kwall-operator
echo "[INFO] Checking eBPF node capability labels on cluster nodes:"
kubectl get nodes -L kwall.io/ebpf-ready,kwall.io/lsm-supported,kwall.io/xdp-supported

echo "=================================================================="
echo "  [SUCCESS] KWALL successfully deployed across all 3 KinD nodes!"
echo "=================================================================="
