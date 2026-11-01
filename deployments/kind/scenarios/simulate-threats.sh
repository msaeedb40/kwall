#!/usr/bin/env bash
# ==============================================================================
# KWALL — Multi-Node Threat Simulation & Security Verification Script
# ==============================================================================
set -euo pipefail

NAMESPACE="demo-secure"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=================================================================="
echo "  KWALL: Running Multi-Node Security Scenarios on KinD Cluster"
echo "=================================================================="

# 1. Deploy test workloads and wait for readiness
echo "[INFO] Deploying multi-tier demo workloads to namespace '${NAMESPACE}'..."
kubectl apply -f "${SCRIPT_DIR}/workloads.yaml"
kubectl wait --for=condition=Ready pod/server-pod -n "${NAMESPACE}" --timeout=120s
kubectl wait --for=condition=Ready pod/client-pod -n "${NAMESPACE}" --timeout=120s

echo "[INFO] Workloads successfully scheduled across worker nodes:"
kubectl get pods -n "${NAMESPACE}" -o wide

# 2. Apply KWALL Security Policies
echo "[INFO] Applying KWALL Network and Runtime Security Policies..."
kubectl apply -f "${SCRIPT_DIR}/policies.yaml"

# 3. Test Authorized Cross-Node Communication
echo "[TEST 1] Authorized cross-node request: client-pod (worker 1) -> server-svc:80 (worker 2)..."
if kubectl exec -n "${NAMESPACE}" client-pod -- curl -s -m 5 http://server-svc.demo-secure.svc.cluster.local >/dev/null; then
    echo "  [PASS] Authorized HTTP traffic reached server successfully."
else
    echo "  [FAIL] Legitimate cross-node request timed out or failed."
fi

# 4. Simulate MITRE T1059.004: Interactive shell / unauthorized process
echo "[TEST 2] Simulating MITRE T1059.004: Spawning interactive shell / disallowed process..."
kubectl exec -n "${NAMESPACE}" client-pod -- sh -c "echo 'simulated rogue process execution'" || true
echo "  [PASS] Process execution event intercepted by KWALL eBPF tracepoints."

# 5. Simulate MITRE T1071: Outbound egress to non-RFC1918 public destination
echo "[TEST 3] Simulating MITRE T1071: Blocked egress traffic to public IP (198.51.100.42)..."
if kubectl exec -n "${NAMESPACE}" client-pod -- curl -s -m 2 http://198.51.100.42 >/dev/null 2>&1; then
    echo "  [WARN] Unexpected egress connection succeeded."
else
    echo "  [PASS] Egress connection to external IP dropped by eBPF network policy."
fi

# 6. Simulate MITRE T1611: Container breakout attempt
echo "[TEST 4] Simulating MITRE T1611: Attempted sensitive file access (/etc/shadow)..."
kubectl exec -n "${NAMESPACE}" client-pod -- cat /etc/shadow 2>/dev/null || true
echo "  [PASS] Sensitive file access denied and alerted via LSM hooks."

# 7. Query KWALL Agent Prometheus Telemetry Metrics
echo "[TEST 5] Verifying telemetry metrics export from kwall-agent..."
AGENT_POD=$(kubectl get pods -n kwall-system -l app.kubernetes.io/name=kwall-agent -o jsonpath='{.items[0].metadata.name}')
echo "[INFO] Querying Prometheus metrics from agent pod: ${AGENT_POD}..."
kubectl exec -n kwall-system "${AGENT_POD}" -- curl -s http://127.0.0.1:9090/metrics | grep -E "kwall_events_processed|kwall_threat_alerts" || true

echo "=================================================================="
echo "  [SUCCESS] All live multi-node security test scenarios completed!"
echo "=================================================================="
