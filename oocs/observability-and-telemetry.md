# Observability, Metrics & Telemetry

KWALL provides native, high-cardinality observability into Kubernetes network flows, policy evaluations, and security alerts. By combining Prometheus metrics, Grafana Loki structured logs, and OpenTelemetry distributed traces, KWALL offers complete operational visibility with negligible CPU overhead.

---

## Observability Architecture

```
                 ┌───────────────────────────────────────────────┐
                 │             Grafana Unified Dashboard         │
                 └───────────────────────┬───────────────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 │                       │                       │
                 ▼                       ▼                       ▼
      ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
      │     Prometheus     │  │    Grafana Loki    │  │   OpenTelemetry    │
      │ (Bounded Metrics)  │  │ (Structured Logs)  │  │(Distributed Traces)│
      └──────────▲─────────┘  └──────────▲─────────┘  └──────────▲─────────┘
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         │
                             ┌───────────┴───────────┐
                             │  kwall-observability  │
                             │   (Rust Collector)    │
                             └───────────▲───────────┘
                                         │
                            Zero-Copy BPF Ring Buffer
                                         │
                             ┌───────────┴───────────┐
                             │     eBPF Dataplane    │
                             │ (kwall-ebpf on Netkit)│
                             └───────────────────────┘
```

---

## Metric Cardinality Design Principle

> **Important Design Rule**: Do not expose raw, unbounded IP addresses or ephemeral source ports as Prometheus metric labels. High-cardinality values degrade Prometheus scrape performance and inflate TSDB index memory.
>
> In KWALL:
> - **Prometheus**: Aggregates by bounded dimensions (`namespace`, `workload_identity`, `policy_name`, `action`, `protocol`).
> - **Loki & OpenTelemetry**: Capture individual 5-tuple flow records, packet bytes, and microsecond latencies for deep debugging and forensics.

---

## Prometheus Metrics Reference

`kwall-agent` exposes Prometheus metrics on port `9090` at `/metrics`:

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `kwall_packets_total` | Counter | `direction` (`ingress`/`egress`), `protocol` | Total packets processed across all netkit devices. |
| `kwall_packets_dropped_total` | Counter | `direction`, `reason` (`policy_deny`, `ddos_drop`, `invalid_checksum`) | Total packets dropped by eBPF programs. |
| `kwall_bytes_total` | Counter | `direction`, `protocol` | Total byte volume processed by the dataplane. |
| `kwall_conntrack_entries_active` | Gauge | `node` | Current number of active tracked connections in kernel LRU hash map. |
| `kwall_conntrack_table_capacity` | Gauge | `node` | Maximum capacity of the eBPF conntrack map. |
| `kwall_policy_eval_latency_seconds` | Histogram | `direction` | Latency distribution of policy evaluation in the kernel (P50, P95, P99). |
| `kwall_ringbuf_events_total` | Counter | `event_type` (`flow`, `alert`, `drop`) | Total events read from the kernel BPF Ring Buffer. |
| `kwall_ringbuf_drops_total` | Counter | `node` | Events dropped due to ring buffer overflow (indicates userspace lag). |

---

## Structured Flow Logging (Loki)

Network flows captured from the kernel ring buffer are formatted as JSON lines and shipped to Loki:

```json
{
  "timestamp": "2026-10-16T09:45:01.182901Z",
  "node": "worker-node-01",
  "src": {
    "ip": "10.244.1.18",
    "port": 49204,
    "identity": 104,
    "namespace": "production",
    "pod": "frontend-6d9b4-xj8k2"
  },
  "dst": {
    "ip": "10.244.2.40",
    "port": 8080,
    "identity": 208,
    "namespace": "production",
    "pod": "checkout-api-5c77-lm4z9"
  },
  "protocol": "TCP",
  "action": "Allow",
  "policy": "allow-frontend-to-checkout",
  "bytes": 512,
  "packets": 4,
  "tcp_flags": "ACK,PSH"
}
```

---

## OpenTelemetry Distributed Tracing

For cross-service latency diagnosis and security forensics, KWALL generates OpenTelemetry trace spans:
- **Trace Context**: Correlates the kernel-level TCP connection handshake with the application-level request trace ID.
- **Trace Span Attributes**:
  - `kwall.decision`: `Allow` / `Deny`
  - `kwall.latency_ns`: Kernel packet processing duration in nanoseconds
  - `kwall.rule_id`: Specific matching rule within the `KWALLNetworkPolicy`
  - `net.transport`: `ip_tcp`
  - `net.peer.name`: Target service hostname / FQDN
