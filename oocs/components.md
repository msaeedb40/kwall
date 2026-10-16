# KWALL Workspace Components

The KWALL codebase is structured as a modular, high-cohesion Cargo workspace comprising **15 specialized crates**. This architecture cleanly decouples kernel eBPF bytecode, low-level dataplane controllers, Kubernetes operator reconciliation, and user-facing CLI tooling.

---

## Crate Dependency & Hierarchy Map

```
                             ┌───────────────────┐
                             │       kwall       │
                             │ (Unified Runner)  │
                             └─────────┬─────────┘
                                       │
     ┌──────────────────┬──────────────┼──────────────┬──────────────────┐
     ▼                  ▼              ▼              ▼                  ▼
┌──────────────┐ ┌──────────────┐ ┌─────────┐ ┌──────────────┐ ┌────────────────────┐
│ kwall-agent  │ │kwall-controll│ │kwall-cni│ │  kwall-cli   │ │ kwall-observability│
└──────┬───────┘ └──────┬───────┘ └────┬────┘ └──────┬───────┘ └─────────┬──────────┘
       │                │              │             │                   │
       ▼                ▼              ▼             ▼                   ▼
┌──────────────┐ ┌──────────────┐ ┌─────────┐ ┌──────────────┐ ┌────────────────────┐
│kwall-dataplane kwall-policy   │ │kwall-api│ │ kwall-common │ │   kwall-storage    │
└──────┬───────┘ └──────┬───────┘ └─────────┘ └──────────────┘ └────────────────────┘
       │                │
       ▼                ▼
┌──────────────┐ ┌──────────────┐
│  kwall-ebpf  │ │kwall-security│
└──────┬───────┘ └──────────────┘
       │
       ▼
┌──────────────────┐
│kwall-ebpf-common │
└──────────────────┘
```

---

## Workspace Crates Breakdown

### 1. `kwall`
- **Location**: `crates/kwall`
- **Type**: Binary
- **Purpose**: Unified multi-call binary entrypoint. Depending on execution arguments or environment variables (`KWALL_MODE`), it can launch the `kwall-agent`, `kwall-controller`, or `kwall-cni` subsystems.

### 2. `kwall-agent`
- **Location**: `crates/kwall-agent`
- **Type**: Binary & Library
- **Purpose**: Node-level resident daemon.
- **Key Modules**:
  - `orchestrator.rs`: Coordinates node startup, map initialization, and policy synchronization loops.
  - `kernel.rs`: Validates kernel capabilities (`BTF`, `bpffs`, `cgroup v2`) and handles eBPF program lifecycle via Aya.
  - `server.rs`: Hosts local Unix Domain Socket IPC server (`/var/run/kwall/kwall.sock`) for the CLI.

### 3. `kwall-controller`
- **Location**: `crates/kwall-controller`
- **Type**: Binary & Library
- **Purpose**: Kubernetes operator and cluster-level control plane.
- **Key Modules**:
  - `reconciler.rs`: Uses `kube-rs` runtime reflection to reconcile `KWALLNetworkPolicy`, `KWALLSecurityPolicy`, and `KWALLDDoSPolicy` resources.
  - `identity_allocator.rs`: Maps pod label hashes to unique 32-bit Security Identity IDs (`SecurityIdentity`).

### 4. `kwall-cni`
- **Location**: `crates/kwall-cni`
- **Type**: Binary & Library
- **Purpose**: CNI plugin conforming to the standard Kubernetes CNI specification (`ADD`, `DEL`, `CHECK`).
- **Key Modules**:
  - `netkit.rs`: Provisions Linux `netkit` virtual network interfaces (`nkp*` on the host side, attached to the pod netns). Automatically loads TC egress/ingress BPF programs.

### 5. `kwall-dataplane`
- **Location**: `crates/kwall-dataplane`
- **Type**: Library
- **Purpose**: Userspace management of kernel eBPF maps and TC/XDP attachments.
- **Key Modules**:
  - `manager.rs`: High-level controller for attaching/detaching programs to network interfaces.
  - `maps.rs`: Type-safe abstractions for updating BPF LPM trie, Hash, and Array maps.
  - `events.rs`: Ingests raw ring buffer byte streams and parses them into structured event types.

### 6. `kwall-ebpf`
- **Location**: `crates/kwall-ebpf`
- **Type**: eBPF Target Binary (`bpfel-unknown-none`)
- **Purpose**: In-kernel eBPF programs compiled with `aya-ebpf`.
- **Key Modules**:
  - `main.rs`: Entrypoint for TC classifiers (`tc_ingress`, `tc_egress`) and XDP filters.
  - `packet.rs`: Direct zero-copy packet parser for Ethernet, IPv4, IPv6, TCP, UDP, and ICMP headers.
  - `maps.rs`: BPF map definitions (Conntrack map, Policy table, Metrics array, Event ring buffer).

### 7. `kwall-ebpf-common`
- **Location**: `crates/kwall-ebpf-common`
- **Type**: Library (`#![no_std]`)
- **Purpose**: Shared memory structures between kernel-space eBPF and userspace Rust.
- **Features**: `#[repr(C)]` memory layouts, copy-safe structs, packet keys, flow records, and event definitions.

### 8. `kwall-policy`
- **Location**: `crates/kwall-policy`
- **Type**: Library
- **Purpose**: Security policy compiler and Intermediate Representation (IR) engine.
- **Key Modules**:
  - `compiler.rs`: Compiles high-level Kubernetes CRD rules into low-level 5-tuple lookup entries.
  - `ir.rs`: Strongly-typed Intermediate Representation for firewall rule trees.
  - `optimizer.rs`: Merges redundant CIDRs, deduplicates rules, and optimizes LPM trie depth.

### 9. `kwall-security`
- **Location**: `crates/kwall-security`
- **Type**: Library
- **Purpose**: Threat mitigation, volumetric DDoS defense, and behavioral heuristics.
- **Key Modules**:
  - `ddos.rs`: Implements SYN-flood tracking, UDP rate-limiting buckets, and ICMP throttling.
  - `anomaly.rs`: Detects abnormal connection rates, port scanning behavior, and protocol anomalies.
  - `supply_chain.rs`: Correlates binary file hashes, network connections, and workload identities.

### 10. `kwall-runtime`
- **Location**: `crates/kwall-runtime`
- **Type**: Library
- **Purpose**: OS runtime, cgroup v2, and process tracing.
- **Key Modules**:
  - `cgroup.rs`: Discovers and monitors cgroup v2 paths for container runtimes (containerd, CRI-O).
  - `process.rs`: Tracks process execve events and maps PIDs to Kubernetes pod identities.

### 11. `kwall-observability`
- **Location**: `crates/kwall-observability`
- **Type**: Library
- **Purpose**: Metrics, structured logs, and OpenTelemetry distributed tracing.
- **Key Modules**:
  - `metrics.rs`: Prometheus metrics registry with P95/P99 latency histograms and packet counters.
  - `logs.rs`: Structured JSON logging engine optimized for Grafana Loki ingestion.

### 12. `kwall-storage`
- **Location**: `crates/kwall-storage`
- **Type**: Library
- **Purpose**: Local state persistence, BPF pinned map registry, and cached endpoint state across agent restarts.

### 13. `kwall-api`
- **Location**: `crates/kwall-api`
- **Type**: Library
- **Purpose**: Kubernetes CRD definitions and Rust data models derived via `kube::CustomResource`. Contains OpenAPI schemas for network policies, DDoS policies, flow policies, and security policies.

### 14. `kwall-cli`
- **Location**: `crates/kwall-cli`
- **Type**: Binary
- **Purpose**: Administrative command-line utility for engineers to inspect eBPF maps, live flows, firewall rules, and node health.

### 15. `kwall-common`
- **Location**: `crates/kwall-common`
- **Type**: Library
- **Purpose**: Cluster-wide constants, Unix domain socket protocol definitions, shared error types (`thiserror`), and cryptographic hash helpers.
