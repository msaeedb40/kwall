use std::sync::atomic::{AtomicU64, Ordering};
use kwall_ebpf_common::MetricsCounter;

#[derive(Default)]
pub struct PrometheusMetrics {
    pub packets_total: AtomicU64,
    pub bytes_total: AtomicU64,
    pub drops_total: AtomicU64,
    pub policy_decisions_total: AtomicU64,
    pub bpf_events_total: AtomicU64,
    pub ringbuf_drops_total: AtomicU64,
    // Latency histogram buckets in microseconds: [1us, 5us, 10us, 25us, 50us, 100us, +Inf]
    pub latency_bucket_1us: AtomicU64,
    pub latency_bucket_5us: AtomicU64,
    pub latency_bucket_10us: AtomicU64,
    pub latency_bucket_25us: AtomicU64,
    pub latency_bucket_50us: AtomicU64,
    pub latency_bucket_100us: AtomicU64,
    pub latency_bucket_inf: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub latency_count: AtomicU64,
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

    pub fn record_ringbuf_drop(&self) {
        self.ringbuf_drops_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_latency_us(&self, latency_us: u64) {
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);

        if latency_us <= 1 {
            self.latency_bucket_1us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 5 {
            self.latency_bucket_5us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 10 {
            self.latency_bucket_10us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 25 {
            self.latency_bucket_25us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 50 {
            self.latency_bucket_50us.fetch_add(1, Ordering::Relaxed);
        }
        if latency_us <= 100 {
            self.latency_bucket_100us.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_bucket_inf.fetch_add(1, Ordering::Relaxed);
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
             kwall_policy_decisions_total {}\n\
             # HELP kwall_ringbuf_drops_total Total ring buffer drops due to queue overflow\n\
             # TYPE kwall_ringbuf_drops_total counter\n\
             kwall_ringbuf_drops_total {}\n\
             # HELP kwall_bpf_latency_microseconds eBPF dataplane execution latency histogram\n\
             # TYPE kwall_bpf_latency_microseconds histogram\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"1\"}} {}\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"5\"}} {}\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"10\"}} {}\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"25\"}} {}\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"50\"}} {}\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"100\"}} {}\n\
             kwall_bpf_latency_microseconds_bucket{{le=\"+Inf\"}} {}\n\
             kwall_bpf_latency_microseconds_sum {}\n\
             kwall_bpf_latency_microseconds_count {}\n",
            self.packets_total.load(Ordering::Relaxed),
            self.bytes_total.load(Ordering::Relaxed),
            self.drops_total.load(Ordering::Relaxed),
            self.policy_decisions_total.load(Ordering::Relaxed),
            self.ringbuf_drops_total.load(Ordering::Relaxed),
            self.latency_bucket_1us.load(Ordering::Relaxed),
            self.latency_bucket_5us.load(Ordering::Relaxed),
            self.latency_bucket_10us.load(Ordering::Relaxed),
            self.latency_bucket_25us.load(Ordering::Relaxed),
            self.latency_bucket_50us.load(Ordering::Relaxed),
            self.latency_bucket_100us.load(Ordering::Relaxed),
            self.latency_bucket_inf.load(Ordering::Relaxed),
            self.latency_sum_us.load(Ordering::Relaxed),
            self.latency_count.load(Ordering::Relaxed),
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
        metrics.record_latency_us(4);

        let output = metrics.render_prometheus();
        assert!(output.contains("kwall_packets_total 1"));
        assert!(output.contains("kwall_bytes_total 1500"));
        assert!(output.contains("kwall_packets_dropped_total 1"));
        assert!(output.contains("kwall_bpf_latency_microseconds_bucket{le=\"5\"} 1"));
    }
}
