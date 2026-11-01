#!/usr/bin/env bash
# ==============================================================================
# KWALL — Build Container Images & Pre-Load into 3-Node KinD Cluster
# ==============================================================================
set -euo pipefail

CLUSTER_NAME="kwall-cluster"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "=================================================================="
echo "  KWALL: Building & Loading Container Images into KinD Nodes"
echo "=================================================================="

cd "${REPO_ROOT}"

# 1. Build release binaries locally if needed, or build Docker images
echo "[INFO] Building Docker image for kwall-agent:latest..."
docker build -t kwall-agent:latest -f deployments/docker/Dockerfile.agent .

echo "[INFO] Building Docker image for kwall-operator:latest..."
docker build -t kwall-operator:latest -f deployments/docker/Dockerfile.operator .

# 2. Pre-load images directly into all 3 KinD nodes
echo "[INFO] Pre-loading kwall-agent:latest into cluster '${CLUSTER_NAME}' nodes..."
kind load docker-image kwall-agent:latest --name="${CLUSTER_NAME}"

echo "[INFO] Pre-loading kwall-operator:latest into cluster '${CLUSTER_NAME}' nodes..."
kind load docker-image kwall-operator:latest --name="${CLUSTER_NAME}"

echo "=================================================================="
echo "  [SUCCESS] Container images successfully pre-loaded across nodes!"
echo "=================================================================="
