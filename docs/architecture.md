# KWALL Architecture Blueprint

**KWALL** is an enterprise-grade, cloud-native Kubernetes security platform driven by **eBPF (Extended Berkeley Packet Filter)** in Rust. It delivers real-time zero-trust security, container process sandboxing, L3–L7 network micro-segmentation, kernel-level application security (WAF), and automated compliance reporting without performance-heavy sidecars.

---

## 1. System High-Level Topology

```
+---------------------------------------------------------------------------------------------------+
|                                  KWALL MULTI-CLUSTER MANAGEMENT PLANE                             |
|                                                                                                   |
|  +-----------------------------+   +-----------------------------+   +-------------------------+  |
|  |   Web Management Console    |   |    Unified GraphQL Gateway   |   |   OpenAPI v3 REST API   |  |
|  |  (Topology / Alerts / WAF)  |   |    (Async Multi-Cluster)    |   |  (SIEM / SOAR Ingestion)|  |
|  +-----------------------------+   +-----------------------------+   +-------------------------+  |
|                                   \               |               /                               |
|                                    v              v              v                                |
|                                 +-----------------------------------+                             |
|                                 |   Kubernetes Gateway API (v1)     |                             |
|                                 | (HTTPRoute / TLS / SameSite CSRF) |                             |
|                                 +-----------------------------------+                             |
+---------------------------------------------------|-----------------------------------------------+
                                                    |
                                                    v
+---------------------------------------------------------------------------------------------------+
|                                KUBERNETES CLUSTER WORKER NODES                                    |
|                                                                                                   |
|   +-------------------------------------------------------------------------------------------+   |
|   |                              USERSPACE NODE AGENT & SERVICES                              |   |
|   |                                                                                           |   |
|   |  +----------------------+  +---------------------+  +----------------------------------+  |   |
|   |  | Event Router & Queue |  |   Detection Engine  |  | Risk Engine & Multi-Factor Score |  |   |
|   |  |  (High-Throughput)   |  | (Sigma / Behavioral)|  |     (MITRE ATT&CK Mapping)       |  |   |
|   |  +----------------------+  +---------------------+  +----------------------------------+  |   |
|   |             ^                         |                              |                    |   |
|   |             |                         v                              v                    |   |
|   |  +----------------------+  +---------------------+  +----------------------------------+  |   |
|   |  | Threat Intelligence  |  | Forensics & Chained |  |   Application Security / WAF     |  |   |
|   |  | (MISP / STIX2 / OTX) |  |   Audit Recorder    |  |  (OWASP / Stream Regex Matcher)  |  |   |
|   |  +----------------------+  +---------------------+  +----------------------------------+  |   |
|   |             ^                         ^                              ^                    |   |
|   +-------------|-------------------------|------------------------------|--------------------+   |
|                 |                         |                              |                        |
|       BPF Ring Buffers          BPF Ring Buffers               BPF Sockmap (sk_msg)               |
|                 |                         |                              |                        |
|   +-------------|-------------------------|------------------------------|--------------------+   |
|   |             v                         v                              v    LINUX KERNEL    |   |
|   |                                                                                           |   |
|   |  [ XDP Driver Fast-Path ]  ===> Sub-microsecond DDoS mitigation & L3/L4 packet drop       |   |
|   |  [ TC Ingress / Egress  ]  ===> Pod network micro-segmentation & DNS query tracking       |   |
|   |  [ BPF LSM Security     ]  ===> Zero-overhead process sandbox (`bprm_check`, `file_open`) |   |
|   |  [ Tracepoints/Kprobes  ]  ===> Process execution, socket lifecycle, and FIM file audits  |   |
|   |  [ Socket sk_msg/sk_skb ]  ===> In-kernel HTTP/1.1, HTTP/2 & gRPC payload interception   |   |
|   |  [ Uprobe TLS Intercept ]  ===> OpenSSL, Rustls, and Go `crypto/tls` cleartext inspection |   |
|   |                                                                                           |   |
|   +-------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Kernel Data Plane (`ebpf/`)
* **XDP Driver Mode**: Pre-stack packet filtering capable of dropping millions of packets per second with sub-microsecond latency.
* **Traffic Control (TC)**: Ingress and egress filters attached to container virtual ethernet pairs (`veth`) enforcing namespace-level network security.
* **BPF LSM (Linux Security Module)**: Real-time container sandboxing intercepting `bprm_check_security`, `file_open`, `task_fix_setuid`, and `socket_connect`.
* **Socket Buffer Streaming (`sk_msg`)**: Intercepts TCP socket buffers directly in kernel memory before userspace copy, enabling inline L7 WAF inspection.
* **Dynamic TLS Uprobes**: Hooks userspace cryptographic libraries (`libssl.so`, `rustls`, `crypto/tls`) to inspect plaintext without private keys or proxy certificates.

### 2.2 Event Routing & Telemetry (`crates/kwall-event-router`, `crates/kwall-telemetry`)
* Non-blocking ingestion of millions of events per second from kernel ring buffers.
* Zero-copy parsing with monotonic microsecond timestamps.
* Prometheus metrics exporter on `/metrics` tracking drop counters, latency histograms, and eBPF hook health.

### 2.3 Threat Detection Engine (`services/detection-engine`)
* Correlates kernel events with behavioral models and Sigma-compatible detection rules.
* Detects container escapes, privilege escalation, reverse shells, defense evasion, and crypto-mining activity.
* Categorizes alerts according to the **MITRE ATT&CK for Containers** framework.

### 2.4 Multi-Factor Risk Engine (`services/risk-engine`)
* Continuously scores workloads (0–100) based on runtime anomalies, CVE vulnerabilities from SBOM analysis, network exposure, and behavioral drift.
* Quantizes risk into actionable tiers: `Nominal`, `Elevated`, `High`, and `Critical`.

### 2.5 L7 Application Security & WAF (`services/application-security`)
* Inline payload normalizer decoding Hex, URL (`%20`, `+`), and Unicode encodings.
* Real-time pattern matching for SQL Injection (SQLi), Cross-Site Scripting (XSS), Server-Side Request Forgery (SSRF), Command Injection, and Path Traversal.
* Atomic socket termination for malicious streams.

### 2.6 Incident Forensics & Audit Chaining (`crates/kwall-forensics`, `crates/kwall-api/src/audit.rs`)
* Reconstructs end-to-end incident timelines across processes, file writes, and network connections.
* Immutable administrative audit trail using a cryptographic **SHA-256 hash chain** from genesis to head.

### 2.7 Management Plane & GraphQL Gateway (`api/graphql/`, `deployments/dashboard/`)
* Async GraphQL query engine for multi-cluster topology, workload risk inspection, and alert triage.
* Single-pane-of-glass web console with interactive SVG topology, live alert triage with one-click pod quarantine, visual policy builder, and automated compliance scorecard dials.
* Double-submit cookie and HTTP header anti-CSRF/XSRF protection.
