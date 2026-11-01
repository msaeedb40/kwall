//! Prometheus metrics registry and exposition generator.

use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe registry containing all atomic Prometheus counters and gauges for KWALL.
#[derive(Debug, Default)]
pub struct TelemetryRegistry {
    // Kernel packet & flow counters
    pub packets_passed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub bytes_ingress: AtomicU64,
    pub bytes_egress: AtomicU64,

    // eBPF Ring Buffer & Ingestion counters
    pub ring_buffer_events_submitted: AtomicU64,
    pub ring_buffer_events_dropped: AtomicU64,
    pub agent_memory_bytes: AtomicU64,

    // Security & Threat Detection counters
    pub threat_alerts_critical: AtomicU64,
    pub threat_alerts_high: AtomicU64,
    pub threat_alerts_medium: AtomicU64,
    pub threat_alerts_low: AtomicU64,
    pub policy_evaluations_allowed: AtomicU64,
    pub policy_evaluations_blocked: AtomicU64,
}

impl TelemetryRegistry {
    /// Creates a new empty TelemetryRegistry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments passed packet count and byte volume.
    pub fn record_packet_passed(&self, bytes: u64) {
        self.packets_passed.fetch_add(1, Ordering::Relaxed);
        self.bytes_ingress.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increments dropped packet count.
    pub fn record_packet_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an event consumed from the eBPF ring buffer.
    pub fn record_ring_buffer_event(&self) {
        self.ring_buffer_events_submitted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records dropped ring buffer events due to backpressure.
    pub fn record_ring_buffer_drop(&self) {
        self.ring_buffer_events_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records a security alert by severity.
    pub fn record_threat_alert(&self, severity: &str) {
        match severity.to_lowercase().as_str() {
            "critical" => self.threat_alerts_critical.fetch_add(1, Ordering::Relaxed),
            "high" | "error" => self.threat_alerts_high.fetch_add(1, Ordering::Relaxed),
            "medium" | "warning" => self.threat_alerts_medium.fetch_add(1, Ordering::Relaxed),
            _ => self.threat_alerts_low.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Records policy evaluation outcome.
    pub fn record_policy_eval(&self, allowed: bool) {
        if allowed {
            self.policy_evaluations_allowed
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.policy_evaluations_blocked
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Updates current memory usage gauge in bytes.
    pub fn set_agent_memory_bytes(&self, bytes: u64) {
        self.agent_memory_bytes.store(bytes, Ordering::Relaxed);
    }

    /// Renders all metrics in standard Prometheus text exposition format (version 0.0.4).
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);

        // kwall_packets_processed_total
        out.push_str(
            "# HELP kwall_packets_processed_total Total network packets processed by XDP/TC.\n",
        );
        out.push_str("# TYPE kwall_packets_processed_total counter\n");
        out.push_str(&format!(
            "kwall_packets_processed_total{{action=\"pass\"}} {}\n",
            self.packets_passed.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "kwall_packets_processed_total{{action=\"drop\"}} {}\n",
            self.packets_dropped.load(Ordering::Relaxed)
        ));

        // kwall_bytes_transferred_total
        out.push_str("# HELP kwall_bytes_transferred_total Total bytes inspected by KWALL.\n");
        out.push_str("# TYPE kwall_bytes_transferred_total counter\n");
        out.push_str(&format!(
            "kwall_bytes_transferred_total{{direction=\"ingress\"}} {}\n",
            self.bytes_ingress.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "kwall_bytes_transferred_total{{direction=\"egress\"}} {}\n",
            self.bytes_egress.load(Ordering::Relaxed)
        ));

        // kwall_ring_buffer_events_total
        out.push_str(
            "# HELP kwall_ring_buffer_events_total Total eBPF events received via ring buffer.\n",
        );
        out.push_str("# TYPE kwall_ring_buffer_events_total counter\n");
        out.push_str(&format!(
            "kwall_ring_buffer_events_total {}\n",
            self.ring_buffer_events_submitted.load(Ordering::Relaxed)
        ));

        // kwall_ring_buffer_events_dropped_total
        out.push_str("# HELP kwall_ring_buffer_events_dropped_total Total events dropped due to channel capacity.\n");
        out.push_str("# TYPE kwall_ring_buffer_events_dropped_total counter\n");
        out.push_str(&format!(
            "kwall_ring_buffer_events_dropped_total {}\n",
            self.ring_buffer_events_dropped.load(Ordering::Relaxed)
        ));

        // kwall_threat_alerts_total
        out.push_str(
            "# HELP kwall_threat_alerts_total Total threat alerts raised by detection engine.\n",
        );
        out.push_str("# TYPE kwall_threat_alerts_total counter\n");
        out.push_str(&format!(
            "kwall_threat_alerts_total{{severity=\"critical\"}} {}\n",
            self.threat_alerts_critical.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "kwall_threat_alerts_total{{severity=\"high\"}} {}\n",
            self.threat_alerts_high.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "kwall_threat_alerts_total{{severity=\"medium\"}} {}\n",
            self.threat_alerts_medium.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "kwall_threat_alerts_total{{severity=\"low\"}} {}\n",
            self.threat_alerts_low.load(Ordering::Relaxed)
        ));

        // kwall_policy_evaluations_total
        out.push_str(
            "# HELP kwall_policy_evaluations_total Security policy rule evaluation count.\n",
        );
        out.push_str("# TYPE kwall_policy_evaluations_total counter\n");
        out.push_str(&format!(
            "kwall_policy_evaluations_total{{result=\"allowed\"}} {}\n",
            self.policy_evaluations_allowed.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "kwall_policy_evaluations_total{{result=\"blocked\"}} {}\n",
            self.policy_evaluations_blocked.load(Ordering::Relaxed)
        ));

        // kwall_agent_memory_bytes
        out.push_str(
            "# HELP kwall_agent_memory_bytes Resident memory bytes used by kwall-agent.\n",
        );
        out.push_str("# TYPE kwall_agent_memory_bytes gauge\n");
        out.push_str(&format!(
            "kwall_agent_memory_bytes {}\n",
            self.agent_memory_bytes.load(Ordering::Relaxed)
        ));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_registry_prom_format() {
        let registry = TelemetryRegistry::new();
        registry.record_packet_passed(1024);
        registry.record_packet_dropped();
        registry.record_threat_alert("critical");
        registry.record_policy_eval(false);
        registry.set_agent_memory_bytes(64 * 1024 * 1024);

        let rendered = registry.render_prometheus();
        assert!(rendered.contains("kwall_packets_processed_total{action=\"pass\"} 1"));
        assert!(rendered.contains("kwall_packets_processed_total{action=\"drop\"} 1"));
        assert!(rendered.contains("kwall_bytes_transferred_total{direction=\"ingress\"} 1024"));
        assert!(rendered.contains("kwall_threat_alerts_total{severity=\"critical\"} 1"));
        assert!(rendered.contains("kwall_policy_evaluations_total{result=\"blocked\"} 1"));
        assert!(rendered.contains("kwall_agent_memory_bytes 67108864"));
    }
}
