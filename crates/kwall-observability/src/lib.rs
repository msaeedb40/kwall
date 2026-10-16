pub mod logs;
pub mod metrics;

pub use logs::{format_flow_for_loki, format_security_event_for_loki, LokiFlowRecord};
pub use metrics::PrometheusMetrics;

pub struct TelemetryPipeline {
    pub metrics: PrometheusMetrics,
}

impl TelemetryPipeline {
    pub fn new() -> Self {
        Self {
            metrics: PrometheusMetrics::new(),
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
    fn test_flow_loki_serialization() {
        let mut flow = FlowEvent::default();
        flow.src_ip[0] = 192;
        flow.src_ip[1] = 168;
        flow.src_ip[2] = 1;
        flow.src_ip[3] = 100;
        flow.dst_port = 443;
        flow.bytes = 1200;

        let json = format_flow_for_loki(&flow);
        assert!(json.contains("192.168.1.100"));
        assert!(json.contains("\"port\":443"));
        assert!(json.contains("\"bytes\":1200"));
    }
}
