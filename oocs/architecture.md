# KWALL Architecture

KWALL implements a decoupled, distributed architecture tailored for Kubernetes clusters running high-performance Linux environments. The platform is divided into two primary planes:
1. **Control Plane**: Manages state, translates declarative CRDs into compiled policy IR, and coordinates cluster-wide workload identities.
2. **Data & Enforcement Plane**: Executes on each Kubernetes node, orchestrating eBPF programs, netkit interfaces, and kernel security hooks.

---

## High-Level Topology

```
                               ┌─────────────────────────────────┐
                               │     Kubernetes API Server       │
                               │  (KWALL CRDs: Policy, DDoS,     │
                               │   Flows, Security)              │
                               └────────────────┬────────────────┘
                                                │
                                                ▼
                               ┌─────────────────────────────────┐
                               │        KWALL Controller         │
                               │  • Identity Allocator           │
                               │  • Policy Compiler & IR Lowering│
                               │  • Endpoint Registry            │
                               └────────────────┬────────────────┘
                                                │ Node Sync / CRDs
            ┌───────────────────────────────────┼───────────────────────────────────┐
            │                                   │                                   │
            ▼                                   ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────┐           ┌───────────────────────┐
│     Node Worker 01    │           │     Node Worker 02    │           │     Node Worker 03    │
│                       │           │                       │           │                       │
│  ┌─────────────────┐  │           │  ┌─────────────────┐  │           │  ┌─────────────────┐  │
│  │  kwall-agent    │  │           │  │  kwall-agent    │  │           │  │  kwall-agent    │  │
│  │  (Rust Daemon)  │  │           │  │  (Rust Daemon)  │  │           │  │  (Rust Daemon)  │  │
│  └────────┬────────┘  │           │  └────────┬────────┘  │           │  └────────┬────────┘  │
│           │ Unix / BPF│           │           │ Unix / BPF│           │           │ Unix / BPF│
│  ┌────────▼────────┐  │           │  ┌────────▼────────┐  │           │  ┌────────▼────────┐  │
│  │ kwall-dataplane │  │           │  │ kwall-dataplane │  │           │  │ kwall-dataplane │  │
│  │ (Map Sync)      │  │           │  │ (Map Sync)      │  │           │  │ (Map Sync)      │  │
│  └────────┬────────┘  │           │  └────────┬────────┘  │           │  └────────┬────────┘  │
│           │           │           │           │           │           │           │           │
│  ═════════╪═════════  │           │  ═════════╪═════════  │           │  ═════════╪═════════  │
│  Linux Kernel         │           │  Linux Kernel         │           │  Linux Kernel         │
│  ┌────────▼────────┐  │           │  ┌────────▼────────┐  │           │  ┌────────▼────────┐  │
│  │ eBPF Programs   │  │           │  │ eBPF Programs   │  │           │  │ eBPF Programs   │  │
│  │ • TC Classifier │  │           │  │ • TC Classifier │  │           │  │ • TC Classifier │  │
│  │ • XDP Filter    │  │           │  │ • XDP Filter    │  │           │  │ • XDP Filter    │  │
│  │ • LSM Hooks     │  │           │  │ • LSM Hooks     │  │           │  │ • LSM Hooks     │  │
│  │ • netkit Devs   │  │           │  │ • netkit Devs   │  │           │  │ • netkit Devs   │  │
│  └─────────────────┘  │           │  └─────────────────┘  │           │  └─────────────────┘  │
└───────────────────────┘           └───────────────────────┘           └───────────────────────┘
```

---

## Subsystem Details

### 1. KWALL Controller (`kwall-controller`)
- **Role**: Cluster-scoped deployment running as a Kubernetes controller.
- **Responsibilities**:
  - Watches `KWALLNetworkPolicy`, `KWALLSecurityPolicy`, `KWALLDDoSPolicy`, and pod metadata.
  - Dynamically computes workload numeric identities (32-bit integers) based on label sets.
  - Generates optimized rule tables and publishes them to per-node stores or CRD statuses.

### 2. KWALL Agent (`kwall-agent`)
- **Role**: Node-scoped daemon running as a Kubernetes `DaemonSet`.
- **Responsibilities**:
  - Interfaces directly with the Linux kernel via the `aya` eBPF library.
  - Mounts BPF filesystems (`/sys/fs/bpf/kwall`), pins maps, and manages lifecycle transitions.
  - Dispatches events via high-performance BPF Ring Buffers to `kwall-observability`.
  - Exposes a local Unix domain socket (`/var/run/kwall/kwall.sock`) for the `kwall-cli`.

### 3. KWALL CNI (`kwall-cni`)
- **Role**: CNI plugin conforming to the container network interface specification.
- **Responsibilities**:
  - Invoked during pod sandbox creation and deletion.
  - Configures **netkit** primary and peer network interfaces (`nkp*` on host, `eth0` in pod).
  - Automatically attaches eBPF TC ingress and egress schedulers onto the netkit primary device.

### 4. Kernel eBPF Subsystem (`kwall-ebpf` & `kwall-ebpf-common`)
- **Execution Hookpoints**:
  - **TC (Traffic Control)**: Direct packet classification on `netkit` devices for ingress/egress firewalling and conntrack.
  - **XDP (eXpress Data Path)**: Early-drop wire-speed packet filtering on physical host interfaces for volumetric DDoS defense.
  - **BPF LSM**: Kernel security policy hooks preventing privilege escalation, unauthorized namespace switching, and illicit binary execution.
  - **cgroup / Sockops**: Socket-level redirect and accelerated TCP handshakes for local pod-to-pod communications.

---

## Communication Models

| Source | Target | Protocol | Description |
| :--- | :--- | :--- | :--- |
| `kwall-controller` | Kubernetes API | HTTPS / TLS | Watches CRDs, pods, and nodes; updates status fields. |
| `kwall-agent` | `kwall-controller` | gRPC / K8s CRD | Synchronizes cluster-wide identity mappings and policy graphs. |
| `kwall-cli` | `kwall-agent` | Unix Domain Socket | Local diagnostics, table dumping, and live flow streaming. |
| Kernel eBPF | `kwall-agent` | BPF Ring Buffer | Zero-copy kernel-to-userspace alert and flow telemetry streams. |
| `kwall-agent` | Kernel eBPF | BPF Maps | Atomic policy updates, conntrack tables, and identity maps. |
