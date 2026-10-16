# Linux Kernel Requirements & Compatibility

KWALL is designed to leverage modern Linux kernel capabilities to achieve maximum packet processing performance and advanced security sandboxing.

---

## Supported Kernel Versions

| Kernel Version | Status | Notes |
| :--- | :--- | :--- |
| **< 6.8** | **Unsupported** | Lacks standard `netkit` virtual network device drivers and modern BPF LSM hooks. |
| **6.8 – 6.12** | **Minimum Supported** | Fully functional eBPF TC, basic netkit, cgroup v2, and BPF LSM support. |
| **Linux 7.x** | **Recommended** | Optimal performance, full netkit zero-copy forwarding, and enhanced BTF relocation. |

---

## Required Kernel Subsystems

```
Production KWALL Node Requirements:
Linux Kernel >= 6.8 (Recommended 7.x)
 ├── eBPF & BPF JIT Compiler
 ├── BTF (BPF Type Format) enabled (/sys/kernel/btf/vmlinux)
 ├── CO-RE (Compile Once – Run Everywhere)
 ├── netkit Network Device Driver
 ├── cgroup v2 Unified Hierarchy
 ├── bpffs Mounted at /sys/fs/bpf
 ├── BPF LSM (Linux Security Module)
 ├── kprobes & tracepoints
 ├── socket / sockmap / sockops BPF
 └── Linux Namespaces (Net, Mount, PID, IPC, UTS)
```

---

## Kernel Config Flags Matrix

To verify that your host kernel supports KWALL, verify the following kernel config parameters (typically located in `/boot/config-$(uname -r)` or `/proc/config.gz`):

| Kernel Option | Required Value | Purpose |
| :--- | :--- | :--- |
| `CONFIG_BPF` | `y` | Core BPF interpreter and foundation |
| `CONFIG_BPF_SYSCALL` | `y` | Enable `bpf()` system call |
| `CONFIG_BPF_JIT` | `y` | Just-In-Time native code compilation for eBPF |
| `CONFIG_DEBUG_INFO_BTF` | `y` | BTF type generation for CO-RE relocations |
| `CONFIG_NETKIT` | `m` or `y` | High-efficiency netkit container networking driver |
| `CONFIG_NET_CLS_ACT` | `y` | Traffic Control actions infrastructure |
| `CONFIG_NET_SCH_INGRESS` | `y` | Ingress TC scheduling hook |
| `CONFIG_NET_SCH_EGRESS` | `y` | Egress TC scheduling hook |
| `CONFIG_BPF_LSM` | `y` | BPF Linux Security Module hook execution |
| `CONFIG_CGROUP_BPF` | `y` | Attach BPF programs to cgroup hierarchy |
| `CONFIG_BPF_STREAM_PARSER` | `y` | Sockmap parsing and fast-path TCP forwarding |

---

## BPF CO-RE (Compile Once – Run Everywhere)

KWALL compiles eBPF C/Rust bytecodes against standard reference vmlinux BTF headers using Aya:
- **Zero Kernel Headers on Nodes**: Nodes do not require `linux-headers` or LLVM/Clang installed.
- **Relocation Engine**: Aya relocates struct offsets dynamically during program load by reading `/sys/kernel/btf/vmlinux` directly on the host.

---

## Required Linux Capabilities

When running `kwall-agent` as a containerized DaemonSet on Kubernetes nodes, the pod security context must grant the following capabilities:

| Capability | Purpose |
| :--- | :--- |
| `CAP_BPF` | Load eBPF programs and manage BPF maps (available in Linux ≥ 5.8). |
| `CAP_NET_ADMIN` | Configure netkit interfaces, TC filters, and IP route tables. |
| `CAP_NET_RAW` | Raw socket operations and packet inspection. |
| `CAP_PERFMON` | Inspect system-wide performance and tracepoints. |
| `CAP_SYS_ADMIN` | Fallback on kernels where `CAP_BPF` is not decoupled; manage BPF mounts. |

---

## Sysctl Recommendations

For high-throughput nodes processing millions of packets per second, configure the following sysctl parameters:

```bash
# Enable BPF JIT hardening and compilation
sysctl -w net.core.bpf_jit_enable=1
sysctl -w net.core.bpf_jit_harden=2

# Increase eBPF JIT memory limit
sysctl -w net.core.bpf_jit_limit=1073741824

# Increase socket receive and send buffers for high throughput
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.netdev_max_backlog=100000
```
