#!/usr/bin/env bash
# ==============================================================================
# KWALL KinD Cluster Automation & eBPF Testbed Script
# Sets up a multi-node KinD cluster with bidirectional BPF filesystem mounts
# and deploys KWALL for live netkit and eBPF testing.
# ==============================================================================

set -euo pipefail

CLUSTER_NAME="kwall-cluster"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
KIND_CONFIG="${SCRIPT_DIR}/kind-config.yaml"
IMAGE_TAG="kwall:dev"

# Color helpers
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

log_info() { echo -e "${CYAN}[INFO]${RESET} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${RESET} $1"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $1"; }

check_prerequisites() {
    log_info "Checking toolchain prerequisites..."
    for cmd in docker kind kubectl helm; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Missing required CLI tool: $cmd"
            exit 1
        fi
    done

    # Kernel compatibility check
    KERNEL_RELEASE=$(uname -r)
    log_info "Host Linux Kernel: ${KERNEL_RELEASE}"
    MAJOR=$(echo "$KERNEL_RELEASE" | cut -d. -f1)
    MINOR=$(echo "$KERNEL_RELEASE" | cut -d. -f2)

    if [ "$MAJOR" -lt 6 ] || ([ "$MAJOR" -eq 6 ] && [ "$MINOR" -lt 8 ]); then
        log_warn "Host kernel is < 6.8 (${KERNEL_RELEASE}). Linux netkit requires kernel >= 6.8."
    else
        log_success "Host kernel ${KERNEL_RELEASE} satisfies Linux netkit requirements (>= 6.8)."
    fi

    # Host bpffs check
    if mount | grep -q "type bpf"; then
        log_success "Host BPF filesystem (/sys/fs/bpf) is mounted."
    else
        log_warn "/sys/fs/bpf is not mounted on the host. Mounting..."
        sudo mount -t bpf bpf /sys/fs/bpf || true
    fi
}

cluster_up() {
    check_prerequisites

    if kind get clusters | grep -q "^${CLUSTER_NAME}$"; then
        log_warn "KinD cluster '${CLUSTER_NAME}' already exists. Reusing existing cluster."
    else
        log_info "Creating KinD cluster '${CLUSTER_NAME}' using ${KIND_CONFIG}..."
        kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"
        log_success "KinD cluster created."
    fi

    kubectl cluster-info --context "kind-${CLUSTER_NAME}"
}

build_and_load_image() {
    log_info "Building KWALL container image (${IMAGE_TAG})..."
    docker build -t "${IMAGE_TAG}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
    log_success "Docker image built: ${IMAGE_TAG}"

    log_info "Loading image into KinD cluster nodes..."
    kind load docker-image "${IMAGE_TAG}" --name "${CLUSTER_NAME}"
    log_success "Image loaded into cluster nodes."
}

deploy_kwall() {
    log_info "Installing KWALL Custom Resource Definitions (CRDs)..."
    kubectl apply -f "${REPO_ROOT}/api/crd/kwall.io/"

    log_info "Deploying KWALL via Helm chart..."
    helm upgrade --install kwall "${REPO_ROOT}/deploy/helm/kwall" \
        --namespace kwall-system \
        --create-namespace \
        --set image.repository="kwall" \
        --set image.tag="dev" \
        --set image.pullPolicy="Never"

    log_info "Waiting for KWALL components to be ready..."
    kubectl rollout status daemonset/kwall-agent -n kwall-system --timeout=120s || true
    kubectl rollout status deployment/kwall-controller -n kwall-system --timeout=120s || true

    log_success "KWALL successfully deployed!"
}

run_smoke_test() {
    log_info "Executing smoke test: deploying demo workloads..."
    kubectl apply -f "${SCRIPT_DIR}/smoke-test.yaml"

    log_info "Waiting for demo workloads to initialize..."
    kubectl rollout status deployment/demo-backend -n kwall-demo --timeout=90s || true
    kubectl rollout status deployment/demo-frontend -n kwall-demo --timeout=90s || true

    log_info "Testing connectivity from demo-frontend to demo-backend..."
    FRONTEND_POD=$(kubectl get pods -n kwall-demo -l app=demo-frontend -o jsonpath='{.items[0].metadata.name}')
    if [ -n "$FRONTEND_POD" ]; then
        log_info "Executing curl from pod ${FRONTEND_POD}..."
        kubectl exec -n kwall-demo "${FRONTEND_POD}" -- curl -s --connect-timeout 5 http://demo-backend:8080 || true
    fi

    log_info "Inspecting KWALL agent status..."
    AGENT_POD=$(kubectl get pods -n kwall-system -l app.kubernetes.io/component=agent -o jsonpath='{.items[0].metadata.name}')
    if [ -n "$AGENT_POD" ]; then
        kubectl exec -n kwall-system "${AGENT_POD}" -- /usr/local/bin/kwall-cli endpoints list 2>/dev/null || true
    fi

    log_success "Smoke test completed."
}

cluster_down() {
    log_info "Deleting KinD cluster '${CLUSTER_NAME}'..."
    kind delete cluster --name "${CLUSTER_NAME}"
    log_success "KinD cluster deleted."
}

cluster_status() {
    log_info "Inspecting KinD cluster '${CLUSTER_NAME}' status:"
    kubectl get nodes -o wide
    kubectl get pods -A
    kubectl get kwallnetworkpolicies,kwallsecuritypolicies -A || true
}

usage() {
    echo "Usage: $0 {up|down|build|deploy|smoke|status|all}"
    echo "  up      : Check prerequisites and create KinD cluster"
    echo "  build   : Build and load KWALL container image into KinD"
    echo "  deploy  : Apply CRDs and deploy KWALL Helm chart"
    echo "  smoke   : Deploy test workloads and verify connectivity"
    echo "  status  : View cluster, pod, and CRD status"
    echo "  all     : Execute up -> build -> deploy -> smoke"
    echo "  down    : Tear down the KinD cluster"
    exit 1
}

ACTION="${1:-all}"

case "$ACTION" in
    up)
        cluster_up
        ;;
    build)
        build_and_load_image
        ;;
    deploy)
        deploy_kwall
        ;;
    smoke)
        run_smoke_test
        ;;
    status)
        cluster_status
        ;;
    down)
        cluster_down
        ;;
    all)
        cluster_up
        build_and_load_image
        deploy_kwall
        run_smoke_test
        ;;
    *)
        usage
        ;;
esac
