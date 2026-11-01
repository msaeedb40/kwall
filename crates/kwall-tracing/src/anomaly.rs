//! Service topology anomaly detection, unprecedented edge detection, and latency degradation analytics.
//!
//! Evaluates active service communication edges against learned dependency baselines,
//! alerting on unauthorized cross-namespace connections and anomalous performance spikes.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};

/// Anomaly detection engine analyzing service communication graphs.
pub struct TopologyAnomalyDetector {
    /// Approved baseline communication edges: `(source_service, target_service)`.
    pub approved_edges: RwLock<HashSet<(String, String)>>,
    /// Expected baseline p99 latencies (microseconds).
    pub baseline_p99_us: RwLock<HashMap<(String, String), u64>>,
    /// Expected baseline request rates per minute.
    pub baseline_request_rates: RwLock<HashMap<(String, String), u64>>,
}

impl Default for TopologyAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TopologyAnomalyDetector {
    /// Creates a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            approved_edges: RwLock::new(HashSet::new()),
            baseline_p99_us: RwLock::new(HashMap::new()),
            baseline_request_rates: RwLock::new(HashMap::new()),
        }
    }

    /// Teaches an approved communication edge and expected performance metrics.
    pub fn learn_edge(
        &self,
        source: &str,
        target: &str,
        expected_p99_us: u64,
        expected_rate_per_min: u64,
    ) {
        let key = (source.to_string(), target.to_string());
        {
            let mut edges = self.approved_edges.write().unwrap();
            edges.insert(key.clone());
        }
        {
            let mut latencies = self.baseline_p99_us.write().unwrap();
            latencies.insert(key.clone(), expected_p99_us);
        }
        {
            let mut rates = self.baseline_request_rates.write().unwrap();
            rates.insert(key, expected_rate_per_min);
        }
    }

    /// Evaluates an active edge observation against the topology baseline.
    pub fn inspect_edge(
        &self,
        source: &str,
        target: &str,
        port: u16,
        current_p99_us: u64,
        current_req_rate: u64,
    ) -> Option<ThreatAlert> {
        let now = kwall_common::utilities::current_timestamp_ns();
        let key = (source.to_string(), target.to_string());

        // 1. Unprecedented Communication Edge Detection
        let is_approved = {
            let edges = self.approved_edges.read().unwrap();
            if edges.is_empty() {
                true // No baseline trained yet; fail open
            } else {
                edges.contains(&key)
            }
        };

        if !is_approved {
            return Some(ThreatAlert::new(
                format!("topo-unprecedented-edge-{}", now),
                now,
                Severity::Error,
                ThreatCategory::TopologyAnomaly,
                Some("T1021"),
                "Unprecedented Service Communication Edge Detected",
                format!(
                    "Unprecedented communication link established from '{source}' to '{target}' on port {port}"
                ),
                None,
                serde_json::json!({
                    "source_service": source,
                    "target_service": target,
                    "port": port
                }),
                "Review Kubernetes network policy to verify whether this inter-service dependency is legitimate"
                    .to_string(),
            ));
        }

        // 2. Latency Degradation Check (p99 > 3x baseline)
        if let Some(&baseline_p99) = self.baseline_p99_us.read().unwrap().get(&key) {
            if baseline_p99 > 0 && current_p99_us >= baseline_p99.saturating_mul(3) {
                return Some(ThreatAlert::new(
                    format!("topo-latency-degradation-{}", now),
                    now,
                    Severity::Warning,
                    ThreatCategory::TopologyAnomaly,
                    Some("T1499"),
                    "Severe Service Dependency Latency Degradation",
                    format!(
                        "Edge '{source}' -> '{target}' p99 latency ({current_p99_us} µs) exceeded 3x baseline ({baseline_p99} µs)"
                    ),
                    None,
                    serde_json::json!({
                        "source_service": source,
                        "target_service": target,
                        "current_p99_us": current_p99_us,
                        "baseline_p99_us": baseline_p99
                    }),
                    "Inspect target service CPU/memory saturation, thread contention, or downstream bottlenecks"
                        .to_string(),
                ));
            }
        }

        // 3. Traffic Spike Check (rate > 5x baseline)
        if let Some(&baseline_rate) = self.baseline_request_rates.read().unwrap().get(&key) {
            if baseline_rate > 0 && current_req_rate >= baseline_rate.saturating_mul(5) {
                return Some(ThreatAlert::new(
                    format!("topo-traffic-spike-{}", now),
                    now,
                    Severity::Warning,
                    ThreatCategory::TopologyAnomaly,
                    Some("T1499"),
                    "Anomalous Service Traffic Surge Detected",
                    format!(
                        "Edge '{source}' -> '{target}' request rate ({current_req_rate} req/min) surged past 5x baseline ({baseline_rate} req/min)"
                    ),
                    None,
                    serde_json::json!({
                        "source_service": source,
                        "target_service": target,
                        "current_rate": current_req_rate,
                        "baseline_rate": baseline_rate
                    }),
                    "Investigate upstream caller for retry storms, scraping behavior, or denial of service"
                        .to_string(),
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unprecedented_edge_detection() {
        let detector = TopologyAnomalyDetector::new();
        detector.learn_edge("prod/frontend", "prod/backend", 5_000, 100);

        // Allowed edge
        assert!(detector
            .inspect_edge("prod/frontend", "prod/backend", 8080, 5_500, 110)
            .is_none());

        // Unprecedented edge: frontend talking to kube-system/etcd
        let alert = detector.inspect_edge("prod/frontend", "kube-system/etcd", 2379, 1_000, 10);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::TopologyAnomaly);
        assert_eq!(a.severity, Severity::Error);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1021"));
    }

    #[test]
    fn test_latency_degradation_alert() {
        let detector = TopologyAnomalyDetector::new();
        detector.learn_edge("prod/order", "prod/payment", 10_000, 50);

        // Latency degraded to 35,000 µs (> 3x 10,000 µs)
        let alert = detector.inspect_edge("prod/order", "prod/payment", 443, 35_000, 50);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.severity, Severity::Warning);
        assert!(a.title.contains("Latency Degradation"));
    }
}
