//! OpenTelemetry-compatible tracing span abstractions and contextual propagation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenTelemetry-compatible trace and span context for distributed event tracing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceContext {
    /// 128-bit hexadecimal trace identifier (32 chars).
    pub trace_id: String,
    /// 64-bit hexadecimal span identifier (16 chars).
    pub span_id: String,
    /// Optional parent span identifier.
    pub parent_span_id: Option<String>,
    /// Name of the operation or processing stage.
    pub operation_name: String,
    /// Associated structured attributes (e.g., pod name, namespace, interface).
    pub attributes: HashMap<String, String>,
}

impl TraceContext {
    /// Creates a new root trace context.
    pub fn new_root(trace_id: impl Into<String>, operation_name: impl Into<String>) -> Self {
        let span_id = format!(
            "{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        );

        Self {
            trace_id: trace_id.into(),
            span_id,
            parent_span_id: None,
            operation_name: operation_name.into(),
            attributes: HashMap::new(),
        }
    }

    /// Spawns a child span under the current context.
    pub fn new_child(&self, operation_name: impl Into<String>) -> Self {
        let child_span_id = format!(
            "{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                .wrapping_add(1)
        );

        Self {
            trace_id: self.trace_id.clone(),
            span_id: child_span_id,
            parent_span_id: Some(self.span_id.clone()),
            operation_name: operation_name.into(),
            attributes: self.attributes.clone(),
        }
    }

    /// Adds a metadata attribute tag to the trace context.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Formats the context into a standard W3C `traceparent` header string (`00-{trace_id}-{span_id}-01`).
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-01", self.trace_id, self.span_id)
    }

    /// Parses a standard W3C `traceparent` header (`00-{trace_id}-{parent_id}-{trace_flags}`).
    #[must_use]
    pub fn parse_traceparent(raw: &str) -> Option<Self> {
        let parts: Vec<&str> = raw.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        let trace_id = parts[1];
        let parent_id = parts[2];
        let _flags = parts[3];

        if version != "00" || trace_id.len() != 32 || parent_id.len() != 16 {
            return None;
        }

        Some(Self {
            trace_id: trace_id.to_string(),
            span_id: format!(
                "{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0)
            ),
            parent_span_id: Some(parent_id.to_string()),
            operation_name: "distributed_trace".to_string(),
            attributes: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_hierarchy_and_traceparent() {
        let root = TraceContext::new_root("4bf92f3577b34da6a3ce929d0e0e4736", "packet_ingest")
            .with_attribute("k8s.pod.name", "frontend-1234")
            .with_attribute("k8s.namespace", "production");

        assert_eq!(root.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(root
            .to_traceparent()
            .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));

        let child = root.new_child("policy_eval");
        assert_eq!(child.trace_id, root.trace_id);
        assert_eq!(child.parent_span_id, Some(root.span_id));
        assert_eq!(
            child.attributes.get("k8s.pod.name"),
            Some(&"frontend-1234".to_string())
        );
    }
}
