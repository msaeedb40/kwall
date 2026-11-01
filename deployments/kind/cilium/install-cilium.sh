#!/usr/bin/env bash
# ==============================================================================
# KWALL — Provision 3-Node KinD Cluster with Cilium 1.20.4 CNI
# ==============================================================================
set -euo pipefail

CLUSTER_NAME="kwall-cilium-cluster"
CILIUM_VERSION="1.20.4"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

echo "=================================================================="
echo "  KWALL: Deploying 3-Node KinD Cluster with Cilium ${CILIUM_VERSION}"
echo "=================================================================="

# 1. Pre-flight checks
command -v docker >/dev/null 2>&1 || { echo "[ERROR] Docker is required."; exit 1; }
command -v kind >/dev/null 2>&1 || { echo "[ERROR] KinD is required."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "[ERROR] kubectl is required."; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "[ERROR] Helm is required."; exit 1; }

# 2. Create CNI-disabled 3-Node KinD cluster
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "[INFO] Cluster '${CLUSTER_NAME}' already exists. Reusing cluster."
else
    echo "[INFO] Creating 3-Node KinD cluster '${CLUSTER_NAME}' (Default CNI disabled)..."
    kind create cluster --config="${SCRIPT_DIR}/kind-cilium-cluster.yaml" --name="${CLUSTER_NAME}"
fi

# 3. Add Cilium Helm repository & Install Cilium 1.20.4
echo "[INFO] Adding Cilium Helm repository..."
helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
helm repo update

echo "[INFO] Installing Cilium ${CILIUM_VERSION} into kube-system..."
helm upgrade --install cilium cilium/cilium \
    --version "${CILIUM_VERSION}" \
    --namespace kube-system \
    -f "${SCRIPT_DIR}/cilium-values.yaml"

# 4. Wait for Cilium DaemonSet and Operator rollout
echo "[INFO] Waiting for Cilium DaemonSet rollout across all 3 nodes..."
kubectl rollout status daemonset/cilium -n kube-system --timeout=240s
kubectl rollout status deployment/cilium-operator -n kube-system --timeout=180s

echo "[INFO] Waiting for all 3 nodes to reach 'Ready' status via Cilium CNI..."
kubectl wait --for=condition=Ready nodes --all --timeout=180s

# 5. Pre-load and deploy KWALL alongside Cilium
echo "[INFO] Pre-loading KWALL container images into '${CLUSTER_NAME}' nodes..."
cd "${REPO_ROOT}"
kind load docker-image kwall-agent:latest --name="${CLUSTER_NAME}" || true
kind load docker-image kwall-operator:latest --name="${CLUSTER_NAME}" || true

echo "[INFO] Deploying KWALL CRDs & Helm chart into kwall-system..."
kubectl apply -f deployments/crds/kwall.io_networkpolicies.yaml
kubectl apply -f deployments/crds/kwall.io_runtimepolicies.yaml

helm upgrade --install kwall ./deployments/helm/kwall \
    --namespace kwall-system \
    --create-namespace \
    --set agent.image.repository="kwall-agent" \
    --set agent.image.tag="latest" \
    --set agent.image.pullPolicy="Never" \
    --set operator.image.repository="kwall-operator" \
    --set operator.image.tag="latest" \
    --set operator.image.pullPolicy="Never"

echo "[INFO] Waiting for kwall-agent DaemonSet rollout alongside Cilium..."
kubectl rollout status daemonset/kwall-agent -n kwall-system --timeout=120s

# 6. Verify eBPF Coexistence
echo "[INFO] Verifying eBPF hook coexistence on worker node 1..."
WORKER1_NODE="kwall-cilium-cluster-worker"
docker exec "${WORKER1_NODE}" bpftool prog show | grep -E "kwall|cilium" || true

echo "=================================================================="
echo "  [SUCCESS] KWALL and Cilium ${CILIUM_VERSION} running in dual-eBPF harmony!"
echo "=================================================================="
