# KWALL Enterprise Compliance & Cryptographic Audit Guide

KWALL provides automated, continuous compliance auditing backed by kernel-level eBPF state proofs and a tamper-evident audit ledger.

---

## 1. Supported Compliance Frameworks

### 1.1 CIS Kubernetes Benchmark v1.8

| Control ID | Title | KWALL eBPF Technical Evidence |
| :--- | :--- | :--- |
| **CIS 5.2.1** | Kernel LSM Binary Execution & File Protection | `bpf_lsm` hooks `bprm_check_security` and `file_open` block untrusted binaries and protect sensitive files. |
| **CIS 5.3.2** | File Integrity Monitoring (FIM) | Kernel tracepoints detect inode modifications on `/etc/kubernetes`, `/var/lib/kubelet`, and manifest configs. |
| **CIS 5.4.1** | Ingress & Egress Micro-segmentation | XDP and TC egress filters enforce default-deny network policies at wire speed. |
| **CIS 4.1.5** | Host Syscall Audit Ingestion | Ring-buffer ingestion streams raw kernel syscalls to immutable tamper-evident logs. |

### 1.2 SOC 2 Type II (Trust Services Criteria)

| Control ID | Trust Criteria | Implementation in KWALL |
| :--- | :--- | :--- |
| **CC6.1** | Logical Access & Boundary Protection | Uprobe TLS inspection (`SSL_read`/`SSL_write`) validates inter-service mTLS and tokens. |
| **CC6.6** | Immutable Audit Trail | Every administrative action and autonomous remediation is linked via a SHA-256 hash chain. |
| **CC6.8** | Rootkit & Malicious Software Prevention | `kwall-selfprotect` continuously verifies kernel kprobe hook integrity and ring-buffer health. |

### 1.3 PCI-DSS v4.0

| Req ID | Requirement | KWALL eBPF Implementation |
| :--- | :--- | :--- |
| **Req 1.2** | Network Security Controls (CDE Isolation) | TC filters block non-CDE outbound egress from payment-processing namespaces. |
| **Req 6.4** | Web Application Firewall (WAF) | `kwall-application-security` inspects cleartext HTTP streams for SQLi, XSS, and SSRF. |
| **Req 11.5** | File Integrity Monitoring (FIM) | Real-time inode tracking alerts on unauthorized changes to binaries, libraries, and configs. |

---

## 2. Cryptographic Audit Trail (SHA-256 Hash Chaining)

All administrative actions, policy deployments, and autonomous remediation events are permanently sealed into an append-only cryptographic ledger.

### Chaining Formula
For each sequential record $N$:
$$\text{RecordHash}_N = \text{SHA-256}\left(\text{Seq}_N : \text{Timestamp}_N : \text{Actor}_N : \text{Role}_N : \text{Action}_N : \text{Resource}_N : \text{Status}_N : \text{Details}_N : \text{RecordHash}_{N-1}\right)$$

Where $\text{RecordHash}_0$ is anchored to the genesis block:
$$\text{RecordHash}_0 = \text{SHA-256}\left(\text{Payload}_0 : \text{"0000000000000000000000000000000000000000000000000000000000000000"}\right)$$

### Tamper Verification
The `AuditLog::verify_integrity()` API reconstructs the chain from genesis to head. If any record, actor, or parameter is modified retroactively, the verification fails immediately with `AuditError::DigestTampered`.
