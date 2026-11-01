//! KWALL Distributed Tracing, Zero-Instrumentation Service Graphs & Topology Analytics.
//!
//! Provides kernel-level request tracing via eBPF socket monitoring and W3C `traceparent` extraction,
//! automated full-mesh directed service dependency graph construction, OpenTelemetry OTLP / Jaeger
//! export formatting, and real-time topology anomaly detection.

pub mod anomaly;
pub mod exporter;
pub mod kernel_trace;
pub mod service_graph;

use std::sync::Arc;

pub use anomaly::TopologyAnomalyDetector;
pub use exporter::TraceExporter;
pub use kernel_trace::{DistributedSpan, FlowKey, KernelSpanTracker, SpanLogEvent};
pub use service_graph::{
    EdgeMetrics, ServiceEdge, ServiceGraphBuilder, ServiceNode, ServiceTopology,
};

/// High-level engine orchestrating distributed tracing, service graph construction, and anomaly analytics.
pub struct TracingEngine {
    pub span_tracker: Arc<KernelSpanTracker>,
    pub graph_builder: Arc<ServiceGraphBuilder>,
    pub anomaly_detector: Arc<TopologyAnomalyDetector>,
}

impl Default for TracingEngine {
    fn default() -> Self {
        Self::new(5000)
    }
}

impl TracingEngine {
    /// Creates a new TracingEngine with designated span buffer capacity.
    #[must_use]
    pub fn new(span_buffer_capacity: usize) -> Self {
        Self {
            span_tracker: Arc::new(KernelSpanTracker::new(span_buffer_capacity)),
            graph_builder: Arc::new(ServiceGraphBuilder::new()),
            anomaly_detector: Arc::new(TopologyAnomalyDetector::new()),
        }
    }

    /// Exports completed spans as OpenTelemetry OTLP JSON.
    #[must_use]
    pub fn export_otlp(&self, service_name: &str) -> String {
        let spans = self.span_tracker.drain_completed_spans();
        TraceExporter::to_otlp_json(service_name, &spans)
    }

    /// Exports completed spans as Jaeger Batch JSON.
    #[must_use]
    pub fn export_jaeger(&self, service_name: &str) -> String {
        let spans = self.span_tracker.drain_completed_spans();
        TraceExporter::to_jaeger_json(service_name, &spans)
    }

    /// Retrieves the current snapshot of the cluster service communication topology.
    #[must_use]
    pub fn get_service_topology(&self) -> ServiceTopology {
        self.graph_builder.get_topology()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tracing_engine_integration() {
        let engine = TracingEngine::default();

        let s1 = Ipv4Addr::new(10, 244, 1, 5);
        let s2 = Ipv4Addr::new(10, 244, 2, 8);

        engine
            .graph_builder
            .register_service("client", "default", &[s1]);
        engine
            .graph_builder
            .register_service("server", "default", &[s2]);

        let flow = FlowKey::new(s1, 40000, s2, 80);
        engine
            .span_tracker
            .start_span(flow, "client", "GET /status", None, 1_000_000_000);

        let span = engine.span_tracker.finish_span(&flow, 200, 1_002_000_000);
        assert!(span.is_some());

        engine
            .graph_builder
            .record_flow(s1, s2, 80, "HTTP", 2_000, 1024, false);

        let otlp = engine.export_otlp("client");
        assert!(otlp.contains("resourceSpans"));

        let topo = engine.get_service_topology();
        assert_eq!(topo.nodes.len(), 2);
        assert_eq!(topo.edges.len(), 1);
    }
}
