//! Standardized event envelope and payload models for KWALL.

use kwall_core::types::{CgroupId, EventSource, NodeId, ProcessId, Severity};
use serde::{Deserialize, Serialize};

/// Canonical KWALL event envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KwallEvent {
    pub version: u16,
    pub event_id: u128,
    pub timestamp_ns: u64,
    pub node_id: NodeId,
    pub severity: Severity,
    pub source: EventSource,
    pub payload: EventPayload,
}

/// Tagged union of all domain event payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    Network(NetworkEventData),
    Process(ProcessEventData),
    Lsm(LsmEventData),
    Alert(AlertEventData),
}

/// Network flow and packet event details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEventData {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub action: String,
    pub packet_len: u32,
    pub ifindex: u32,
}

/// Process creation and lifecycle event details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEventData {
    pub pid: ProcessId,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: CgroupId,
    pub comm: String,
    pub filename: String,
}

/// LSM access control enforcement details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsmEventData {
    pub pid: ProcessId,
    pub uid: u32,
    pub cgroup_id: CgroupId,
    pub hook_id: u32,
    pub action_taken: String,
}

/// Security violation and threat alert details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEventData {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub mitre_technique: Option<String>,
}
