# KWALL Threat Model & Security Capabilities

KWALL provides holistic defense-in-depth across the entire cloud-native stack: from raw L2/L3 frames to L7 application protocols, container runtimes, process executions, and supply-chain correlations.

---

## Defense Matrix Across Layers

| Layer | Threat Vector | KWALL Detection & Enforcement Mechanism |
| :--- | :--- | :--- |
| **L2 / L3** | IP spoofing, ARP cache poisoning, rogue packet injection | eBPF XDP/TC checks validating source IP against Kubernetes pod CIDR and netkit endpoint MAC bindings. |
| **L4** | SYN flood, UDP amplification, port scanning, unauthorized connection attempts | Connection tracking rate-limiters, XDP SYN-cookie validation, dynamic LPM trie firewall enforcement. |
| **L7** | DNS exfiltration, unauthorized HTTP/gRPC endpoints, rogue external egress | Application-level protocol parser, DNS query audit ring buffers, egress domain restrictions. |
| **Runtime** | Container breakouts, kernel privilege escalation, unauthorized binary exec | BPF LSM (Linux Security Module) hooks blocking `execve`, sensitive `ptrace` calls, and setuid transitions. |
| **Storage / FS** | Credential theft (e.g. ServiceAccount tokens), rootfs tampering | In-kernel file operation filtering (`sys_openat`, `security_file_open`) auditing secret access. |
| **Supply-Chain** | Tampered container binaries, unexpected shell spawns, reverse shells | Binary SHA256/BLAKE3 hash correlation against Kubernetes image manifests, anomalous process trees. |

---

## Detailed Threat Mitigations

### 1. Volumetric DDoS Mitigation (`kwall-security::ddos`)
- **SYN Flood Shield**: At the XDP driver layer, incoming TCP SYN packets are validated against token-bucket rate limits before kernel memory allocation.
- **UDP & ICMP Floods**: Adaptive rate-limiting drops excessive UDP datagrams or ICMP ping storms while preserving established connections.
- **Connection Table Saturation**: Prevents connection exhaustion attacks by enforcing per-source-IP concurrency caps.

### 2. Microsegmentation & Lateral Movement Prevention
- **Identity-Based Isolation**: Unlike traditional firewalls relying purely on volatile IP addresses, KWALL enforces rules using cryptographic 32-bit Security Identities.
- **Default-Deny Ingress & Egress**: Prevents compromised pods from scanning or connecting to sibling workloads within the same Kubernetes namespace or cluster.

### 3. Container Breakout & Privilege Escalation Defense
- **BPF LSM Enforcement**:
  - Blocks `sys_ptrace` calls targeting processes outside the container namespace.
  - Denies unauthorized `mount` and `pivot_root` attempts.
  - Prevents execution of binaries that have gained capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) unexpectedly.
- **Namespace Integrity Checks**: Monitors namespace hierarchy and flags unauthorized namespace switches (`setns`).

### 4. Supply-Chain & Binary Anomaly Detection
- **Process Lineage Verification**: Alerts when an unexpected shell (`/bin/sh`, `/bin/bash`) is spawned by a non-interactive service container (e.g. `nginx`, `redis`).
- **Binary Hash Validation**: Computes BLAKE3 hashes of executed binaries and correlates them with runtime image digests.
- **Reverse Shell Detection**: Identifies immediate network socket connections originating from newly spawned shell processes directed at non-standard ports.

---

## Incident Response & Threat Telemetry

When a security policy violation or anomaly is detected:
1. **Immediate Kernel Drop**: The eBPF program immediately terminates the packet or denies the system call with `-EPERM`.
2. **Zero-Copy Event Generation**: An alert payload (`SecurityEvent`) containing timestamp, pod identity, namespace, source/destination 5-tuple, and violation reason is written to the BPF Ring Buffer.
3. **Userspace Dispatch**: The `kwall-agent` ingests the event and routes it to Prometheus counters, Loki structured logs, and OpenTelemetry trace spans.
