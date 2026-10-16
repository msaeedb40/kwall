use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
}

impl TraceContext {
    pub fn new(trace_id: String, span_id: String) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: None,
        }
    }

    pub fn generate() -> Self {
        let trace_id = format!("{:032x}", rand_u128());
        let span_id = format!("{:016x}", rand_u64());
        Self::new(trace_id, span_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfSpanRecord {
    pub context: TraceContext,
    pub operation_name: String,
    pub start_time_ns: u64,
    pub duration_ns: u64,
    pub attributes: Vec<(String, String)>,
    pub status: String,
}

impl BpfSpanRecord {
    pub fn new_bpf_evaluation(
        operation: &str,
        start_ns: u64,
        duration_ns: u64,
        action: &str,
        src_ip: &str,
        dst_ip: &str,
        dst_port: u16,
    ) -> Self {
        let context = TraceContext::generate();
        Self {
            context,
            operation_name: operation.to_string(),
            start_time_ns: start_ns,
            duration_ns,
            attributes: vec![
                ("kwall.action".to_string(), action.to_string()),
                ("net.peer.ip".to_string(), src_ip.to_string()),
                ("net.host.ip".to_string(), dst_ip.to_string()),
                ("net.host.port".to_string(), dst_port.to_string()),
                ("telemetry.sdk.name".to_string(), "kwall-ebpf".to_string()),
            ],
            status: if action == "DROP" { "ERROR".to_string() } else { "OK".to_string() },
        }
    }

    pub fn to_otlp_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

// Lightweight deterministic pseudo-random generator for traces (no extra dependency needed)
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    (now as u64) ^ 0x517cc1b727220a95
}

fn rand_u128() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    now ^ 0xa0761d6478bd642f517cc1b727220a95
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_creation() {
        let span = BpfSpanRecord::new_bpf_evaluation(
            "ebpf.tc_ingress",
            1000,
            2400,
            "PASS",
            "10.244.1.5",
            "10.244.1.8",
            8080,
        );
        assert_eq!(span.status, "OK");
        assert_eq!(span.context.trace_id.len(), 32);
        assert_eq!(span.context.span_id.len(), 16);
    }
}
