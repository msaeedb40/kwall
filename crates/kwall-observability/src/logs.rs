use kwall_ebpf_common::{FlowEvent, SecurityEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LokiFlowRecord {
    pub timestamp_ns: u64,
    pub src_identity: u32,
    pub dst_identity: u32,
    pub src_ip: String,
    pub dst_ip: String,
    pub port: u16,
    pub protocol: u8,
    pub action: u8,
    pub drop_reason: u8,
    pub bytes: u64,
}

pub fn format_flow_for_loki(flow: &FlowEvent) -> String {
    let src_ip_str = format!(
        "{}.{}.{}.{}",
        flow.src_ip[0], flow.src_ip[1], flow.src_ip[2], flow.src_ip[3]
    );
    let dst_ip_str = format!(
        "{}.{}.{}.{}",
        flow.dst_ip[0], flow.dst_ip[1], flow.dst_ip[2], flow.dst_ip[3]
    );

    let record = LokiFlowRecord {
        timestamp_ns: flow.timestamp_ns,
        src_identity: flow.src_identity,
        dst_identity: flow.dst_identity,
        src_ip: src_ip_str,
        dst_ip: dst_ip_str,
        port: flow.dst_port,
        protocol: flow.protocol,
        action: flow.action,
        drop_reason: flow.drop_reason,
        bytes: flow.bytes,
    };

    serde_json::to_string(&record).unwrap_or_default()
}

pub fn format_security_event_for_loki(event: &SecurityEvent) -> String {
    serde_json::to_string(event).unwrap_or_default()
}
