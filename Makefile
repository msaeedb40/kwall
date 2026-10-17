# ============================================================
# KWALL Makefile
# eBPF-powered Kubernetes firewall & security platform
# ============================================================

SHELL := /bin/bash

PROJECT := kwall
IMAGE ?= kwall
TAG ?= dev

CARGO := cargo
BPF_TARGET := bpfel-unknown-none
RELEASE_DIR := target/release

.PHONY: all
all: fmt lint test build

# ------------------------------------------------------------
# Development
# ------------------------------------------------------------

.PHONY: fmt
fmt:
	$(CARGO) fmt --all -- --check

.PHONY: fmt-fix
fmt-fix:
	$(CARGO) fmt --all

.PHONY: check
check:
	$(CARGO) check --workspace --all-targets

.PHONY: lint
lint:
	$(CARGO) clippy \
		--workspace \
		--all-targets \
		--all-features \
		-- \
		-D warnings

.PHONY: test
test:
	$(CARGO) test --workspace --all-features

# ------------------------------------------------------------
# Userspace
# ------------------------------------------------------------

.PHONY: build
build:
	$(CARGO) build --workspace

.PHONY: release
release:
	$(CARGO) build --workspace --release

.PHONY: run
run:
	$(CARGO) run -p kwall

.PHONY: cli
cli:
	$(CARGO) run -p kwall-cli -- --help

# ------------------------------------------------------------
# eBPF
# ------------------------------------------------------------

.PHONY: ebpf
ebpf:
	$(CARGO) +nightly build \
		-Z build-std=core \
		-p kwall-ebpf \
		--release \
		--target $(BPF_TARGET)

.PHONY: ebpf-debug
ebpf-debug:
	$(CARGO) +nightly build \
		-Z build-std=core \
		-p kwall-ebpf \
		--target $(BPF_TARGET)

# Build userspace + eBPF
.PHONY: build-all
build-all: release ebpf

.PHONY: ebpf-verify
ebpf-verify: ebpf
	$(CARGO) test -p kwall-dataplane --lib verifier::tests::test_verify_real_kwall_ebpf_binary

# ------------------------------------------------------------
# Security / verification
# ------------------------------------------------------------

.PHONY: audit
audit:
	cargo audit || true

.PHONY: deny
deny:
	cargo deny check || true

.PHONY: verify
verify: fmt check lint test
	@echo "KWALL verification passed"

# ------------------------------------------------------------
# Docker
# ------------------------------------------------------------

.PHONY: docker-build
docker-build:
	docker build \
		-t $(IMAGE):$(TAG) \
		-f Dockerfile .

.PHONY: docker-run
docker-run:
	docker run --rm -it \
		--privileged \
		--network host \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-v /sys/kernel/debug:/sys/kernel/debug \
		$(IMAGE):$(TAG)

# ------------------------------------------------------------
# KinD Cluster Testbed
# ------------------------------------------------------------

.PHONY: kind-up
kind-up:
	bash scripts/kind/setup-kind.sh up

.PHONY: kind-down
kind-down:
	bash scripts/kind/setup-kind.sh down

.PHONY: kind-deploy
kind-deploy:
	bash scripts/kind/setup-kind.sh deploy

.PHONY: kind-smoke
kind-smoke:
	bash scripts/kind/setup-kind.sh smoke

.PHONY: kind-all
kind-all:
	bash scripts/kind/setup-kind.sh all

# ------------------------------------------------------------
# Cleanup
# ------------------------------------------------------------

.PHONY: clean
clean:
	$(CARGO) clean
	rm -rf target/

# ------------------------------------------------------------
# Help
# ------------------------------------------------------------

.PHONY: help
help:
	@echo "KWALL build targets:"
	@echo "  make check          Cargo check host workspace"
	@echo "  make fmt            Check formatting"
	@echo "  make fmt-fix        Fix formatting"
	@echo "  make lint           Run Clippy with -D warnings"
	@echo "  make test           Run tests"
	@echo "  make build          Debug build"
	@echo "  make release        Release userspace build"
	@echo "  make ebpf           Release eBPF build (nightly bpfel)"
	@echo "  make build-all      Userspace + eBPF"
	@echo "  make verify         Full verification"
	@echo "  make docker-build   Build container image"
