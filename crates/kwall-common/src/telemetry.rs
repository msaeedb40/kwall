//! In-memory atomic telemetry counters and performance metrics.

use std::sync::atomic::{AtomicU64, Ordering};

/// Node-level atomic performance counters.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub packets_processed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub events_ingested: AtomicU64,
    pub events_dropped_buffer_full: AtomicU64,
    pub policy_evaluations: AtomicU64,
}

impl PipelineMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn inc_packets_processed(&self) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_packets_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_events_ingested(&self) {
        self.events_ingested.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_events_dropped(&self) {
        self.events_dropped_buffer_full
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_policy_evaluations(&self) {
        self.policy_evaluations.fetch_add(1, Ordering::Relaxed);
    }
}
