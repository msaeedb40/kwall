//! Fast normalization from raw eBPF binary events into canonical KwallEvent envelopes.

use kwall_common::utilities::format_ipv4;
use kwall_core::constants::EVENT_PROTOCOL_VERSION;
use kwall_core::types::{CgroupId, EventSource, NodeId, ProcessId, Severity};
use kwall_ebpf_common::events::{BpfLsmEvent, BpfNetEvent, BpfProcessEvent};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::event::{EventPayload, KwallEvent, LsmEventData, NetworkEventData, ProcessEventData};

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Generates a unique monotonic 128-bit event ID.
#[inline]
pub fn next_event_id(node_id: u64) -> u128 {
    let seq = EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    ((node_id as u128) << 64) | (seq as u128)
}

/// Normalizes a binary network event from XDP/TC.
pub fn normalize_net_event(raw: &BpfNetEvent, node_id: NodeId) -> KwallEvent {
    let action_str = match raw.action {
        0 => "allow",
        1 => "block",
        2 => "redirect",
        _ => "audit",
    };

    let severity = match raw.action {
        1 => Severity::Warning,
        _ => Severity::Info,
    };

    KwallEvent {
        version: EVENT_PROTOCOL_VERSION,
        event_id: next_event_id(node_id.0),
        timestamp_ns: raw.timestamp_ns,
        node_id,
        severity,
        source: EventSource::Xdp,
        payload: EventPayload::Network(NetworkEventData {
            src_ip: format_ipv4(raw.src_ip),
            dst_ip: format_ipv4(raw.dst_ip),
            src_port: raw.src_port,
            dst_port: raw.dst_port,
            protocol: raw.protocol,
            action: action_str.to_string(),
            packet_len: raw.packet_len,
            ifindex: raw.ifindex,
        }),
    }
}

/// Normalizes a process execution event from tracepoints.
pub fn normalize_process_event(raw: &BpfProcessEvent, node_id: NodeId) -> KwallEvent {
    let comm = String::from_utf8_lossy(&raw.comm)
        .trim_matches('\0')
        .to_string();

    let filename = String::from_utf8_lossy(&raw.filename)
        .trim_matches('\0')
        .to_string();

    KwallEvent {
        version: EVENT_PROTOCOL_VERSION,
        event_id: next_event_id(node_id.0),
        timestamp_ns: raw.timestamp_ns,
        node_id,
        severity: Severity::Info,
        source: EventSource::TracepointProcess,
        payload: EventPayload::Process(ProcessEventData {
            pid: ProcessId(raw.pid),
            tgid: raw.tgid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            cgroup_id: CgroupId(raw.cgroup_id),
            comm,
            filename,
        }),
    }
}

/// Normalizes an LSM security event.
pub fn normalize_lsm_event(raw: &BpfLsmEvent, node_id: NodeId) -> KwallEvent {
    let action_taken = match raw.action_taken {
        1 => "denied",
        _ => "allowed",
    };

    KwallEvent {
        version: EVENT_PROTOCOL_VERSION,
        event_id: next_event_id(node_id.0),
        timestamp_ns: raw.timestamp_ns,
        node_id,
        severity: Severity::Critical,
        source: EventSource::LsmSecurity,
        payload: EventPayload::Lsm(LsmEventData {
            pid: ProcessId(raw.pid),
            uid: raw.uid,
            cgroup_id: CgroupId(raw.cgroup_id),
            hook_id: raw.hook_id,
            action_taken: action_taken.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_net_event() {
        let raw = BpfNetEvent {
            timestamp_ns: 12345678,
            src_ip: u32::from_ne_bytes([192, 168, 1, 10]),
            dst_ip: u32::from_ne_bytes([10, 0, 0, 1]),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            action: 1, // block
            pad: [0; 2],
            packet_len: 128,
            ifindex: 2,
        };

        let event = normalize_net_event(&raw, NodeId(42));
        assert_eq!(event.node_id, NodeId(42));
        assert_eq!(event.severity, Severity::Warning);

        if let EventPayload::Network(data) = event.payload {
            assert_eq!(data.src_ip, "192.168.1.10");
            assert_eq!(data.dst_ip, "10.0.0.1");
            assert_eq!(data.action, "block");
            assert_eq!(data.packet_len, 128);
        } else {
            panic!("Expected Network payload");
        }
    }

    #[test]
    fn test_normalize_process_event() {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"curl");

        let raw = BpfProcessEvent {
            timestamp_ns: 999999,
            pid: 1234,
            tgid: 1234,
            ppid: 1000,
            uid: 0,
            gid: 0,
            cgroup_id: 8888,
            comm,
            filename: [0u8; 64],
        };

        let event = normalize_process_event(&raw, NodeId(1));
        assert_eq!(event.source, EventSource::TracepointProcess);

        if let EventPayload::Process(data) = event.payload {
            assert_eq!(data.comm, "curl");
            assert_eq!(data.pid, ProcessId(1234));
            assert_eq!(data.cgroup_id, CgroupId(8888));
        } else {
            panic!("Expected Process payload");
        }
    }
}
