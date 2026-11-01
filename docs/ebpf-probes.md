# KWALL eBPF Kernel Probe Matrix & Hook Internals

KWALL attaches specialized eBPF programs across multiple kernel subsystems to achieve defense-in-depth security with minimal overhead (< 1.5% CPU penalty, < 25µs latency).

---

## 1. Kernel Hook Matrix

| Program Type | Target Kernel Hook | Probe Function | Purpose |
| :--- | :--- | :--- | :--- |
| **XDP** (`BPF_PROG_TYPE_XDP`) | NIC Driver Ingress | `xdp_ingress_filter` | Wire-speed DDoS mitigation, SYN flood protection, and IP blocklisting before socket allocation (0.22µs transit). |
| **TC** (`BPF_PROG_TYPE_SCHED_CLS`) | Traffic Control Ingress/Egress | `tc_cls_bpf_filter` | Micro-segmentation, pod-to-pod firewalling, DNS query inspection, and CIDR allowlist enforcement. |
| **LSM** (`BPF_PROG_TYPE_LSM`) | `security_bprm_check` | `lsm_bprm_check` | Zero-overhead process execution sandbox. Prevents unauthorized binaries (`/bin/sh`, `/tmp/*`) from executing. |
| **LSM** (`BPF_PROG_TYPE_LSM`) | `security_file_open` | `lsm_file_open` | File Integrity Monitoring (FIM). Blocks writes to `/etc/shadow`, `/etc/kubernetes`, and container root filesystems. |
| **LSM** (`BPF_PROG_TYPE_LSM`) | `security_task_fix_setuid` | `lsm_task_fix_setuid` | Prevents unauthorized container privilege escalation to root (UID 0). |
| **LSM** (`BPF_PROG_TYPE_LSM`) | `security_socket_connect` | `lsm_socket_connect` | Prevents unauthorized egress connections to external IP ranges or cloud metadata (`169.254.169.254`). |
| **Tracepoint** (`BPF_PROG_TYPE_TRACEPOINT`) | `sched:sched_process_exec` | `tp_sched_process_exec` | High-fidelity process lifecycle tracking, recording PID, PPID, command line arguments, and container cgroup IDs. |
| **Tracepoint** (`BPF_PROG_TYPE_TRACEPOINT`) | `syscalls:sys_enter_connect` | `tp_sys_enter_connect` | Socket creation and outbound connection auditing for SIEM ingestion. |
| **Sockmap** (`BPF_PROG_TYPE_SK_MSG`) | Socket Buffer Filter | `sk_msg_stream_inspect` | Intercepts HTTP/1.1, HTTP/2, and gRPC payload streams in socket memory for real-time WAF inspection before userspace read. |
| **Sockmap** (`BPF_PROG_TYPE_SK_SKB`) | Stream Parser & Verdict | `sk_skb_verdict` | Atomic socket-layer termination (`SK_DROP`) for active OWASP injection attacks. |
| **Uprobe** (`BPF_PROG_TYPE_KPROBE`) | OpenSSL `SSL_write` | `uprobe_ssl_write` | Cleartext inspection of HTTPS payloads before TLS encryption without proxy certificates. |
| **Uprobe** (`BPF_PROG_TYPE_KPROBE`) | OpenSSL `SSL_read` | `uprobe_ssl_read` | Cleartext inspection of inbound HTTPS responses after TLS decryption. |
| **Uprobe** (`BPF_PROG_TYPE_KPROBE`) | Rustls `write_tls` | `uprobe_rustls_write` | In-flight cleartext inspection for modern Rust microservices. |
| **Uprobe** (`BPF_PROG_TYPE_KPROBE`) | Go `crypto/tls.(*Conn).Write` | `uprobe_go_tls_write` | Plaintext inspection for Go-based Kubernetes services and ingress controllers. |

---

## 2. Kernel Map Data Structures

KWALL relies on BPF maps for lockless kernel-to-userspace communication:

```
[ Kernel Probes ] ---> [ BPF Ring Buffers (16 MB) ] ===(zero-copy)===> [ Userspace Event Router ]
                                ^
                                |
[ Userspace Policy Controller ] ===(BPF_MAP_UPDATE)===> [ LPM Trie / Hash Maps (CIDR / Rules) ]
```

1. **`BPF_MAP_TYPE_RINGBUF` (`EVENTS_RINGBUF`)**:
   - Single-producer, multi-consumer ring buffer delivering up to 10M events/sec.
   - Replaces deprecated perf-event buffers with lower overhead and memory safety.
2. **`BPF_MAP_TYPE_LPM_TRIE` (`POLICY_CIDR_MAP`)**:
   - Longest Prefix Match trie for IPv4/IPv6 CIDR lookup in $O(1)$ complexity during packet transit.
3. **`BPF_MAP_TYPE_SOCKHASH` (`SOCK_HASH_MAP`)**:
   - Maps socket file descriptors to container identities for zero-copy stream redirection via `sk_msg`.
4. **`BPF_MAP_TYPE_HASH` (`CONTAINER_CGROUP_MAP`)**:
   - Maps Linux `cgroup2` hierarchy IDs to Kubernetes pod UID, namespace, and workload labels.

---

## 3. Kernel Verification & Safety Constraints

All eBPF programs in KWALL compile with `#![no_std]` using **Rust Aya** and strictly enforce kernel safety rules:
* Bounded loops with static iterations (`#pragma unroll` equivalent).
* Memory boundary checks before reading packet headers (`data + offset > data_end`).
* Zero memory allocations in BPF execution context.
* Compatible with Linux Kernels **5.15+** (LSM BPF requires kernel 5.7+ with `CONFIG_BPF_LSM=y`).
