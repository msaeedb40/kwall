# Custom Resource Definitions (CRDs) & Policy Engine

KWALL extends Kubernetes with five custom resources under the API group `kwall.io/v1alpha1`. These declarative resources allow security operators to define network policies, threat defenses, runtime process security, DDoS mitigation limits, and flow telemetry rules.

---

## 1. `KWALLNetworkPolicy`

`KWALLNetworkPolicy` provides advanced L3–L7 microsegmentation, supporting label selectors, namespace matching, CIDR exceptions, protocol filtering, and custom actions (`Allow`, `Deny`, `Audit`).

### Spec Definition

```yaml
apiVersion: kwall.io/v1alpha1
kind: KWALLNetworkPolicy
metadata:
  name: secure-backend-policy
  namespace: production
spec:
  endpoint_selector:
    match_labels:
      app: payment-api
  ingress:
    - action: Allow
      from_endpoints:
        - match_labels:
            app: frontend
          match_namespaces:
            - production
      ports:
        - protocol: TCP
          port: 8443
    - action: Deny
      from_cidrs:
        - cidr: "0.0.0.0/0"
  egress:
    - action: Allow
      to_endpoints:
        - match_labels:
            app: postgres-db
      ports:
        - protocol: TCP
          port: 5432
    - action: Allow
      to_cidrs:
        - cidr: "10.96.0.10/32" # CoreDNS
      ports:
        - protocol: UDP
          port: 53
```

---

## 2. `KWALLSecurityPolicy`

`KWALLSecurityPolicy` enforces workload-level runtime controls, system call restrictions, process execution rules, and file integrity protection via BPF LSM hooks.

### Spec Definition

```yaml
apiVersion: kwall.io/v1alpha1
kind: KWALLSecurityPolicy
metadata:
  name: lockdown-workload
  namespace: production
spec:
  endpoint_selector:
    match_labels:
      tier: secure
  rules:
    - name: prevent-privilege-escalation
      action: Deny
      scope: Process
      condition: "uid_transition == true && target_uid == 0"
    - name: block-reverse-shells
      action: Deny
      scope: NetworkConnect
      condition: "socket.type == SOCK_STREAM && destination.port IN [4444, 5555, 9001]"
    - name: audit-sensitive-file-reads
      action: Audit
      scope: FileOpen
      condition: "path STARTSWITH '/etc/kubernetes' || path == '/var/run/secrets/kubernetes.io/serviceaccount/token'"
```

---

## 3. `KWALLRuntimePolicy`

`KWALLRuntimePolicy` enforces Linux LSM and BPF runtime integrity on workloads, restricting execution to verified binary hashes, preventing container escape vectors, and blocking execution from untrusted ephemeral directories (e.g., `/tmp`, `/dev/shm`).

### Spec Definition

```yaml
apiVersion: kwall.io/v1alpha1
kind: KWALLRuntimePolicy
metadata:
  name: strict-workload-guard
  namespace: production
spec:
  endpoint_selector:
    match_labels:
      tier: payment-processor
  allowed_binaries:
    - /usr/local/bin/payment-service
    - /usr/bin/busybox
  denied_paths:
    - /tmp
    - /dev/shm
  enforce_binary_hashes: true
  block_container_escape: true
  action: Block
```

---

## 4. `KWALLDDoSPolicy`

`KWALLDDoSPolicy` applies kernel-level rate-limiting and SYN flood defenses at wire-speed directly in the eBPF XDP or TC layer before socket allocation occurs.

### Spec Definition

```yaml
apiVersion: kwall.io/v1alpha1
kind: KWALLDDoSPolicy
metadata:
  name: ingress-ddos-guard
  namespace: ingress-system
spec:
  endpoint_selector:
    match_labels:
      app: ingress-gateway
  syn_flood:
    enabled: true
    rate_limit_per_ip: 500 # max SYN packets/second per source IP
    action: Drop
  udp_rate_limit:
    enabled: true
    max_packets_per_second: 50000
    burst_capacity: 100000
    action: RateLimit
  conntrack_limits:
    max_active_connections_per_ip: 200
```

---

## 5. `KWALLFlowPolicy`

`KWALLFlowPolicy` configures dynamic flow telemetry, sampling ratios, and export destinations without modifying the underlying network configuration.

### Spec Definition

```yaml
apiVersion: kwall.io/v1alpha1
kind: KWALLFlowPolicy
metadata:
  name: sample-external-traffic
  namespace: production
spec:
  endpoint_selector:
    match_labels:
      environment: prod
  sampling_rate: 1 # 1 = capture 100% of flows, 10 = 1 out of 10
  export_targets:
    - type: OpenTelemetry
      endpoint: "otel-collector.observability.svc:4317"
    - type: Loki
      endpoint: "http://loki.observability.svc:3100"
  capture_payload_bytes: 64 # Zero for metadata-only
```

---

## Policy Compilation & Lowering Pipeline

```
  KWALLNetworkPolicy (K8s CRD)
            │
            ▼
  kwall-policy Compiler (AST Parser)
            │
            ├── Label Resolver ────► SecurityIdentity (32-bit ID)
            ├── CIDR Trie Optimizer ──► Radix Tree / LPM Trie
            └── Port & Proto Ranges ─► Bitmap Masks
            │
            ▼
  Policy Intermediate Representation (IR)
            │
            ▼
  kwall-dataplane Map Synchronizer
            │
            ▼
  Kernel BPF Maps (BPF_MAP_TYPE_LPM_TRIE & BPF_MAP_TYPE_HASH)
            │
            ▼
  In-Kernel TC Classifier (Sub-microsecond Decision)
```

1. **Declarative Ingestion**: The controller watches CRD updates using Kubernetes watch streams.
2. **Identity Resolution**: Selectors are converted into numerical 32-bit Security Identity IDs.
3. **IR Compilation**: High-level rules are compiled into normalized 5-tuple lookup tables (`src_id`, `dst_id`, `dst_port`, `proto`, `action`).
4. **Kernel Map Commit**: Rules are committed atomically to pinned BPF maps (`kwall_policy_ingress`, `kwall_policy_egress`), guaranteeing zero downtime and uninterrupted packet flows during updates.
