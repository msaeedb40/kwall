use std::sync::atomic::{AtomicU64, Ordering};
use kwall_ebpf_common::MetricsCounter;

#[derive(Default)]
pub struct PrometheusMetrics {
    pub packets_total: AtomicU64,
    pub bytes_total: AtomicU64,
    pub drops_total: AtomicU64,
    pub policy_decisions_total: AtomicU64,
    pub bpf_events_total: AtomicU64,
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&self, bytes: u64) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_total.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_drop(&self) {
        self.drops_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_policy_decision(&self) {
        self.policy_decisions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_from_dataplane(&self, counter: &MetricsCounter) {
        self.packets_total.store(counter.packets, Ordering::Relaxed);
        self.bytes_total.store(counter.bytes, Ordering::Relaxed);
        self.drops_total.store(counter.drops, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP kwall_packets_total Total number of packets processed by KWALL eBPF\n\
             # TYPE kwall_packets_total counter\n\
             kwall_packets_total {}\n\
             # HELP kwall_bytes_total Total number of bytes processed by KWALL eBPF\n\
             # TYPE kwall_bytes_total counter\n\
             kwall_bytes_total {}\n\
             # HELP kwall_packets_dropped_total Total packets dropped by firewall or DDoS filters\n\
             # TYPE kwall_packets_dropped_total counter\n\
             kwall_packets_dropped_total {}\n\
             # HELP kwall_policy_decisions_total Total policy evaluations evaluated\n\
             # TYPE kwall_policy_decisions_total counter\n\
             kwall_policy_decisions_total {}\n",
            self.packets_total.load(Ordering::Relaxed),
            self.bytes_total.load(Ordering::Relaxed),
            self.drops_total.load(Ordering::Relaxed),
            self.policy_decisions_total.load(Ordering::Relaxed)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_rendering() {
        let metrics = PrometheusMetrics::new();
        metrics.record_packet(1500);
        metrics.record_drop();

        let output = metrics.render_prometheus();
        assert!(output.contains("kwall_packets_total 1"));
        assert!(output.contains("kwall_bytes_total 1500"));
        assert!(output.contains("kwall_packets_dropped_total 1"));
    }
}
