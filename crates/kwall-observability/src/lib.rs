pub mod correlation;
pub mod logs;
pub mod metrics;
pub mod traces;

pub use correlation::{CorrelatedTelemetryEvent, TelemetryCorrelator};
pub use logs::{LokiFlowRecord, format_flow_for_loki, format_security_event_for_loki};
pub use metrics::PrometheusMetrics;
pub use traces::{BpfSpanRecord, TraceContext};

use std::sync::Arc;

pub struct TelemetryPipeline {
    pub metrics: Arc<PrometheusMetrics>,
    pub correlator: TelemetryCorrelator,
}

impl TelemetryPipeline {
    pub fn new() -> Self {
        let metrics = Arc::new(PrometheusMetrics::new());
        let correlator = TelemetryCorrelator::new(metrics.clone());
        Self {
            metrics,
            correlator,
        }
    }
}

impl Default for TelemetryPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_ebpf_common::FlowEvent;

    #[test]
    fn test_pipeline_integration() {
        let pipeline = TelemetryPipeline::new();
        let flow = FlowEvent {
            bytes: 1024,
            action: 1, // DROP
            ..Default::default()
        };

        let (event, span) = pipeline.correlator.process_flow(&flow);
        assert_eq!(event.action, "DROP");
        assert_eq!(span.status, "ERROR");

        let prom_output = pipeline.metrics.render_prometheus();
        assert!(prom_output.contains("kwall_packets_dropped_total 1"));
    }
}
