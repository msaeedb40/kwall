# KWALL Documentation Suite

Welcome to the official documentation for **KWALL** (Kernel-level Workload Armor & Logical Linchpin) — an eBPF-powered Kubernetes firewall and multi-layer security platform.

---

## What is KWALL?

KWALL is a cloud-native security and networking engine built with **Rust 1.99+**, **Aya (eBPF)**, and **netkit**. It delivers transparent, high-throughput packet processing, L3–L7 policy enforcement, and runtime threat detection directly in the Linux kernel without injecting sidecars or intercepting traffic via userspace proxies.

```
                      ┌──────────────────────────────────────┐
                      │        Kubernetes API & CRDs         │
                      └──────────────────┬───────────────────┘
                                         │
                      ┌──────────────────▼───────────────────┐
                      │       KWALL Control Plane (Operator) │
                      │  • Policy Reconciler  • Identity Map │
                      └──────────────────┬───────────────────┘
                                         │ gRPC / CRD State
                ┌────────────────────────┼────────────────────────┐
                ▼                        ▼                        ▼
      ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
      │  Node Agent 01   │     │  Node Agent 02   │     │  Node Agent 03   │
      │  • Aya BPF Loader│     │  • Aya BPF Loader│     │  • Aya BPF Loader│
      │  • Netkit CNI    │     │  • Netkit CNI    │     │  • Netkit CNI    │
      └─────────┬────────┘     └─────────┬────────┘     └─────────┬────────┘
                │                        │                        │
  ══════════════╪════════════════════════╪════════════════════════╪══════════════
  Linux Kernel  │                        │                        │
      ┌─────────▼────────┐     ┌─────────▼────────┐     ┌─────────▼────────┐
      │  eBPF Dataplane  │     │  eBPF Dataplane  │     │  eBPF Dataplane  │
      │  TC • XDP • LSM  │     │  TC • XDP • LSM  │     │  TC • XDP • LSM  │
      │  netkit primary  │     │  netkit primary  │     │  netkit primary  │
      └──────────────────┘     └──────────────────┘     └──────────────────┘
```

---

## Documentation Index

| Document | Description |
| :--- | :--- |
| **[architecture.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/architecture.md)** | High-level and low-level architectural topology, subsystem communications, and data flow. |
| **[kernel-requirements.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/kernel-requirements.md)** | Linux kernel requirements (≥ 6.8, recommended 7.x), eBPF CO-RE, BTF, netkit, and required kernel features. |
| **[components.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/components.md)** | In-depth breakdown of all 15 workspace crates (agent, controller, dataplane, ebpf, policy, security, etc.). |
| **[crds-and-policies.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/crds-and-policies.md)** | Specification of Custom Resource Definitions (`NetworkPolicy`, `SecurityPolicy`, `DDoSPolicy`, `FlowPolicy`). |
| **[dataplane-and-netkit.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/dataplane-and-netkit.md)** | Netkit driver mechanics, eBPF TC hooks, XDP fast-path, and packet processing lifecycles. |
| **[threat-model-and-security.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/threat-model-and-security.md)** | Defense against L2–L7 attacks, DDoS mitigation, runtime exploits, and container breakouts. |
| **[cli-reference.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/cli-reference.md)** | Reference manual for `kwall-cli` subcommands, arguments, and diagnostic inspection tools. |
| **[deployment-and-operations.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/deployment-and-operations.md)** | Helm deployment guide, DaemonSet topology, RBAC permissions, and build instructions. |
| **[observability-and-telemetry.md](file:///home/mb0/Documents/mylabdrive2/kwall/oocs/observability-and-telemetry.md)** | Prometheus metrics, OpenTelemetry distributed tracing, and Loki event logging architecture. |

---

## Key Highlights

- **Pure Rust Userspace & Kernel-Space**: Unified memory safety, deterministic concurrency, and zero C dependencies in the eBPF layer.
- **netkit Native**: Leveraging Linux netkit virtual network devices for superior throughput and reduced overhead compared to legacy `veth` pairs.
- **Identity-Aware Enforcement**: Packets are stamped and evaluated against cryptographic numeric identities derived from Kubernetes pod labels and namespaces.
- **eBPF CO-RE (Compile Once – Run Everywhere)**: Single binary bytecode distribution using kernel BTF introspection.
- **Zero-Copy Event Pipeline**: BPF Ring Buffers dispatch high-frequency security events and telemetry directly into userspace without memory copies.
