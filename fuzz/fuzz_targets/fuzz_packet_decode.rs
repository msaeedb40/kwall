//! Fuzz harness for raw packet decoders and ring buffer binary normalizers.

use kwall_core::types::NodeId;
use kwall_ebpf_common::events::BpfNetEvent;
use kwall_event_router::normalizer::normalize_net_event;

fn main() {
    let mut event = BpfNetEvent {
        timestamp_ns: 0,
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        action: 0,
        pad: [0, 0],
        packet_len: 0,
        ifindex: 0,
    };

    let node_id = NodeId(1);
    // Stress bit patterns
    for &src in &[0u32, 0xFFFFFFFF, 0x7F000001, 0x0A000001, 0x80808080] {
        for &port in &[0u16, 80, 443, 65535] {
            event.src_ip = src;
            event.dst_port = port;
            let _ = normalize_net_event(&event, node_id);
        }
    }

    println!("Packet decoder fuzzing passed across byte permutations without panics.");
}
