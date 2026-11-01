#!/usr/bin/env bash
# ==============================================================================
# KWALL — KinD Cluster Teardown Script
# ==============================================================================
set -euo pipefail

CLUSTER_NAME="kwall-cluster"

echo "[INFO] Deleting KinD cluster '${CLUSTER_NAME}'..."
kind delete cluster --name="${CLUSTER_NAME}"
echo "[SUCCESS] KinD cluster '${CLUSTER_NAME}' deleted."
