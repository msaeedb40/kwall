#!/usr/bin/env bash
# ==============================================================================
# KWALL — Multi-Node KinD Cluster Setup Script (3 Nodes: 1 Control-Plane, 2 Workers)
# ==============================================================================
set -euo pipefail

CLUSTER_NAME="kwall-cluster"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/kind-cluster.yaml"

echo "=================================================================="
echo "  KWALL: Deploying 3-Node KinD Cluster for eBPF Zero-Trust Testing"
echo "=================================================================="

# 1. Pre-flight checks
command -v docker >/dev/null 2>&1 || { echo "[ERROR] Docker is required but not installed."; exit 1; }
command -v kind >/dev/null 2>&1 || { echo "[ERROR] KinD (Kubernetes-in-Docker) is required but not installed."; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "[ERROR] kubectl is required but not installed."; exit 1; }

# 2. Check host eBPF / BTF support
if [[ -f "/sys/kernel/btf/vmlinux" ]]; then
    echo "[INFO] Host kernel BTF detected at /sys/kernel/btf/vmlinux (CO-RE enabled)."
else
    echo "[WARN] /sys/kernel/btf/vmlinux not found on host. Standard BPF CO-RE might require BTF generation."
fi

# 3. Create KinD cluster if not already existing
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "[INFO] Cluster '${CLUSTER_NAME}' already exists. Reusing existing cluster."
else
    echo "[INFO] Creating 3-node KinD cluster '${CLUSTER_NAME}' from ${CONFIG_FILE}..."
    kind create cluster --config="${CONFIG_FILE}" --name="${CLUSTER_NAME}"
fi

# 4. Wait for all 3 nodes to report Ready
echo "[INFO] Waiting for all 3 nodes (1 control-plane, 2 workers) to reach 'Ready' status..."
kubectl wait --for=condition=Ready nodes --all --timeout=180s

echo "[INFO] Cluster Nodes Status:"
kubectl get nodes -o wide

# 5. Ensure BPF filesystem (bpffs) is mounted with Bidirectional propagation on every node
NODES=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')
for node in $NODES; do
    echo "[INFO] Verifying bpffs on node: ${node}..."
    docker exec "${node}" mount | grep -q "/sys/fs/bpf" || {
        echo "[INFO] Mounting bpffs on ${node}..."
        docker exec "${node}" mount -t bpf bpffs /sys/fs/bpf
    }
done

echo "=================================================================="
echo "  [SUCCESS] 3-Node KinD Cluster '${CLUSTER_NAME}' is Ready!"
echo "  Control-Plane: kwall-cluster-control-plane"
echo "  Worker 1:      kwall-cluster-worker"
echo "  Worker 2:      kwall-cluster-worker2"
echo "=================================================================="
