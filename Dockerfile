# ============================================================
# KWALL
# eBPF-powered Kubernetes firewall & security platform
# ============================================================

# ------------------------------------------------------------
# Build stage
# ------------------------------------------------------------
FROM rust:1.99-bookworm AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        pkg-config \
        build-essential \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates ./crates

# Build userspace release binaries
RUN cargo build --workspace --release

# ------------------------------------------------------------
# Runtime stage
# ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

WORKDIR /opt/kwall

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        procps && \
    rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=builder /build/target/release/kwall /usr/local/bin/kwall
COPY --from=builder /build/target/release/kwall-cli /usr/local/bin/kwall-cli
COPY --from=builder /build/target/release/kwall-cni /opt/cni/bin/kwall

# Runtime directories
RUN mkdir -p /etc/kwall /var/lib/kwall /var/log/kwall /run/kwall

ENV KWALL_CONFIG=/etc/kwall/kwall.yaml

ENTRYPOINT ["/usr/local/bin/kwall"]
CMD ["agent"]
