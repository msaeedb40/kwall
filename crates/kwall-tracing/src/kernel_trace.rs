//! Kernel-level distributed tracing, socket correlation, and W3C traceparent context extraction.
//!
//! Reconstructs end-to-end distributed trace spans across Kubernetes services without
//! bytecode instrumentation or manual SDK modifications.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

use kwall_telemetry::tracing::TraceContext;
use serde::{Deserialize, Serialize};

/// Detailed discrete event occurring within the lifecycle of a distributed span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLogEvent {
    pub timestamp_ns: u64,
    pub name: String,
    pub attributes: HashMap<String, String>,
}

/// A zero-instrumentation distributed trace span reconstructed from eBPF socket events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub service_name: String,
    pub operation_name: String,
    pub start_time_ns: u64,
    pub end_time_ns: u64,
    pub duration_ns: u64,
    pub status_code: u16,
    pub error: bool,
    pub attributes: HashMap<String, String>,
    pub events: Vec<SpanLogEvent>,
}

/// Active in-flight connection tracking key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

impl FlowKey {
    #[must_use]
    pub fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }
}

/// In-flight span tracker managing active kernel socket interactions.
pub struct KernelSpanTracker {
    in_flight: RwLock<HashMap<FlowKey, DistributedSpan>>,
    completed_spans: RwLock<Vec<DistributedSpan>>,
    max_completed_buffer: usize,
}

impl Default for KernelSpanTracker {
    fn default() -> Self {
        Self::new(5000)
    }
}

impl KernelSpanTracker {
    /// Creates a tracker with a designated completed span buffer capacity.
    #[must_use]
    pub fn new(max_completed_buffer: usize) -> Self {
        Self {
            in_flight: RwLock::new(HashMap::new()),
            completed_spans: RwLock::new(Vec::with_capacity(max_completed_buffer)),
            max_completed_buffer,
        }
    }

    /// Records the start of an L7 request or socket connection.
    pub fn start_span(
        &self,
        flow: FlowKey,
        service_name: &str,
        operation_name: &str,
        traceparent: Option<&str>,
        start_time_ns: u64,
    ) {
        let (trace_id, parent_span_id) = if let Some(tp) = traceparent {
            if let Some(ctx) = TraceContext::parse_traceparent(tp) {
                (ctx.trace_id, ctx.parent_span_id)
            } else {
                (Self::generate_trace_id(), None)
            }
        } else {
            (Self::generate_trace_id(), None)
        };

        let span_id = Self::generate_span_id();
        let mut attributes = HashMap::new();
        attributes.insert("net.peer.ip".to_string(), flow.dst_ip.to_string());
        attributes.insert("net.peer.port".to_string(), flow.dst_port.to_string());
        attributes.insert("net.host.ip".to_string(), flow.src_ip.to_string());
        attributes.insert("net.host.port".to_string(), flow.src_port.to_string());

        let span = DistributedSpan {
            trace_id,
            span_id,
            parent_span_id,
            service_name: service_name.to_string(),
            operation_name: operation_name.to_string(),
            start_time_ns,
            end_time_ns: 0,
            duration_ns: 0,
            status_code: 0,
            error: false,
            attributes,
            events: Vec::new(),
        };

        let mut in_flight = self.in_flight.write().unwrap();
        in_flight.insert(flow, span);
    }

    /// Appends an event to an active span.
    pub fn add_event(
        &self,
        flow: &FlowKey,
        name: &str,
        timestamp_ns: u64,
        attrs: HashMap<String, String>,
    ) {
        let mut in_flight = self.in_flight.write().unwrap();
        if let Some(span) = in_flight.get_mut(flow) {
            span.events.push(SpanLogEvent {
                timestamp_ns,
                name: name.to_string(),
                attributes: attrs,
            });
        }
    }

    /// Finalizes a span upon response completion or connection closure.
    pub fn finish_span(
        &self,
        flow: &FlowKey,
        status_code: u16,
        end_time_ns: u64,
    ) -> Option<DistributedSpan> {
        let mut span = {
            let mut in_flight = self.in_flight.write().unwrap();
            in_flight.remove(flow)?
        };

        span.end_time_ns = end_time_ns;
        span.duration_ns = end_time_ns.saturating_sub(span.start_time_ns);
        span.status_code = status_code;
        span.error = status_code >= 400;

        let mut completed = self.completed_spans.write().unwrap();
        if completed.len() >= self.max_completed_buffer {
            completed.remove(0);
        }
        completed.push(span.clone());

        Some(span)
    }

    /// Flushes all completed spans accumulated in memory.
    pub fn drain_completed_spans(&self) -> Vec<DistributedSpan> {
        let mut completed = self.completed_spans.write().unwrap();
        std::mem::take(&mut *completed)
    }

    /// Generates a random 32-character hex trace ID.
    fn generate_trace_id() -> String {
        let now = kwall_common::utilities::current_timestamp_ns();
        let hash = kwall_l7::crypto::sha256_hex(&now.to_le_bytes());
        hash[..32].to_string()
    }

    /// Generates a random 16-character hex span ID.
    fn generate_span_id() -> String {
        let now = kwall_common::utilities::current_timestamp_ns();
        let hash = kwall_l7::crypto::sha256_hex(&now.to_be_bytes());
        hash[..16].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_span_tracking_lifecycle() {
        let tracker = KernelSpanTracker::new(10);
        let flow = FlowKey::new(
            Ipv4Addr::new(10, 244, 1, 10),
            40120,
            Ipv4Addr::new(10, 244, 2, 80),
            8080,
        );

        // Start span with existing traceparent
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        tracker.start_span(
            flow,
            "order-service",
            "POST /api/v1/orders",
            Some(traceparent),
            1_000_000_000,
        );

        // Add span event
        let mut attrs = HashMap::new();
        attrs.insert("cache.hit".to_string(), "true".to_string());
        tracker.add_event(&flow, "cache_lookup", 1_000_100_000, attrs);

        // Finish span
        let finished = tracker
            .finish_span(&flow, 200, 1_005_000_000)
            .expect("Span should exist");
        assert_eq!(finished.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(finished.parent_span_id.as_deref(), Some("00f067aa0ba902b7"));
        assert_eq!(finished.duration_ns, 5_000_000);
        assert!(!finished.error);
        assert_eq!(finished.events.len(), 1);

        // Verify drain
        let spans = tracker.drain_completed_spans();
        assert_eq!(spans.len(), 1);
        assert!(tracker.drain_completed_spans().is_empty());
    }
}
