//! Unified detection engine integrating baseline profiling, runtime heuristics, and network analytics.

use crate::alert::ThreatAlert;
use crate::baseline::BaselineEngine;
use crate::network::{NetworkDetectorConfig, NetworkThreatDetector};
use crate::runtime::RuntimeThreatDetector;
use kwall_event_enricher::enricher::EnrichedEvent;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;

/// Core configuration for the KWALL Detection Engine.
#[derive(Debug, Clone)]
pub struct DetectionEngineConfig {
    /// Initial baseline learning period in nanoseconds (e.g. 1 hour = 3,600,000,000,000 ns).
    pub baseline_learning_duration_ns: u64,
    /// Network detection configuration.
    pub network_config: NetworkDetectorConfig,
    /// Capacity of the alert broadcast channel.
    pub alert_channel_capacity: usize,
}

impl Default for DetectionEngineConfig {
    fn default() -> Self {
        Self {
            baseline_learning_duration_ns: 3_600_000_000_000, // 1 hour
            network_config: NetworkDetectorConfig::default(),
            alert_channel_capacity: 1024,
        }
    }
}

/// Unified Detection Engine orchestrating behavioral baselining and threat detection.
pub struct DetectionEngine {
    baseline: BaselineEngine,
    runtime_detector: RuntimeThreatDetector,
    network_detector: NetworkThreatDetector,
    alert_tx: broadcast::Sender<ThreatAlert>,
    total_alerts: AtomicU64,
}

impl DetectionEngine {
    /// Creates a new DetectionEngine with specified configuration.
    pub fn new(config: DetectionEngineConfig) -> Self {
        let (alert_tx, _) = broadcast::channel(config.alert_channel_capacity);
        Self {
            baseline: BaselineEngine::new(config.baseline_learning_duration_ns),
            runtime_detector: RuntimeThreatDetector::new(),
            network_detector: NetworkThreatDetector::new(config.network_config),
            alert_tx,
            total_alerts: AtomicU64::new(0),
        }
    }

    /// Evaluates an enriched event against all detection components and broadcasts alerts.
    pub fn process_event(&self, event: &EnrichedEvent) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        // 1. Behavioral baseline check
        if let Some(alert) = self.baseline.process_event(event) {
            alerts.push(alert);
        }

        // 2. Runtime heuristics
        alerts.extend(self.runtime_detector.evaluate(event));

        // 3. Network heuristics
        alerts.extend(self.network_detector.evaluate(event));

        // Broadcast and update metrics
        for alert in &alerts {
            self.total_alerts.fetch_add(1, Ordering::Relaxed);
            let _ = self.alert_tx.send(alert.clone());
        }

        alerts
    }

    /// Subscribes to the live stream of detected threat alerts.
    pub fn subscribe(&self) -> broadcast::Receiver<ThreatAlert> {
        self.alert_tx.subscribe()
    }

    /// Returns the total number of security alerts raised.
    pub fn total_alerts_raised(&self) -> u64 {
        self.total_alerts.load(Ordering::Relaxed)
    }

    /// Access the underlying baseline engine.
    pub fn baseline(&self) -> &BaselineEngine {
        &self.baseline
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new(DetectionEngineConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{CgroupId, EventSource, NodeId, ProcessId, Severity};
    use kwall_event_router::event::{EventPayload, KwallEvent, ProcessEventData};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_detection_engine_broadcast() {
        let engine = Arc::new(DetectionEngine::default());
        let mut rx = engine.subscribe();

        let event = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 99,
                timestamp_ns: 1234567,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(10),
                    tgid: 10,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    cgroup_id: CgroupId(1),
                    comm: "bash".to_string(),
                    filename: "/bin/bash".to_string(),
                }),
            },
            src_workload: None,
            dst_workload: None,
        };

        let alerts = engine.process_event(&event);
        assert!(!alerts.is_empty());
        assert_eq!(engine.total_alerts_raised(), alerts.len() as u64);

        let received = rx.recv().await.expect("Should receive broadcast alert");
        assert_eq!(received.title, "Interactive Shell Spawned: bash");
    }
}
