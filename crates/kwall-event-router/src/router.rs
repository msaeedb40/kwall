//! High-throughput asynchronous event dispatcher and worker pool.

use kwall_common::telemetry::PipelineMetrics;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::event::KwallEvent;

/// Handler trait for processing routed events.
pub trait EventHandler: Send + Sync + 'static {
    fn handle(&self, event: &KwallEvent);
}

/// Asynchronous event router with bounded queues and worker pool.
pub struct EventRouter {
    tx: mpsc::Sender<KwallEvent>,
    metrics: Arc<PipelineMetrics>,
}

impl EventRouter {
    /// Spawns a new EventRouter with the configured queue capacity and worker threads.
    pub fn spawn<H: EventHandler>(
        queue_capacity: usize,
        num_workers: usize,
        handler: Arc<H>,
        metrics: Arc<PipelineMetrics>,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<KwallEvent>(queue_capacity);

        // Spawn async dispatcher worker
        let handler_clone = Arc::clone(&handler);
        let metrics_clone = Arc::clone(&metrics);

        tokio::spawn(async move {
            debug!(
                "EventRouter background dispatcher started with {} workers",
                num_workers
            );
            while let Some(event) = rx.recv().await {
                metrics_clone.inc_events_ingested();
                handler_clone.handle(&event);
            }
            debug!("EventRouter background dispatcher stopped");
        });

        Self { tx, metrics }
    }

    /// Dispatches an event into the processing pipeline with backpressure.
    pub fn dispatch(&self, event: KwallEvent) -> Result<(), Box<KwallEvent>> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(dropped)) => {
                self.metrics.inc_events_dropped();
                warn!("Event queue buffer full; dropping event to preserve pipeline latency");
                Err(Box::new(dropped))
            }
            Err(mpsc::error::TrySendError::Closed(event)) => {
                warn!("Event dispatcher channel closed");
                Err(Box::new(event))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventPayload, NetworkEventData};
    use kwall_core::types::{EventSource, NodeId, Severity};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestHandler {
        processed_count: AtomicUsize,
    }

    impl EventHandler for TestHandler {
        fn handle(&self, _event: &KwallEvent) {
            self.processed_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_event_dispatch() {
        let metrics = Arc::new(PipelineMetrics::new());
        let handler = Arc::new(TestHandler {
            processed_count: AtomicUsize::new(0),
        });

        let router = EventRouter::spawn(16, 2, Arc::clone(&handler), Arc::clone(&metrics));

        let event = KwallEvent {
            version: 1,
            event_id: 100,
            timestamp_ns: 1_000_000,
            node_id: NodeId(1),
            severity: Severity::Info,
            source: EventSource::Xdp,
            payload: EventPayload::Network(NetworkEventData {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "10.0.0.2".to_string(),
                src_port: 8080,
                dst_port: 80,
                protocol: 6,
                action: "allow".to_string(),
                packet_len: 64,
                ifindex: 1,
            }),
        };

        assert!(router.dispatch(event).is_ok());

        // Yield to allow background worker task to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(handler.processed_count.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.events_ingested.load(Ordering::Relaxed), 1);
    }
}
