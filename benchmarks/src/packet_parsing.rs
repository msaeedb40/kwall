//! Benchmark suite for raw packet parsing and binary event decoding.

use kwall_core::types::NodeId;
use kwall_ebpf_common::events::BpfNetEvent;
use kwall_event_router::normalizer::normalize_net_event;
use std::time::Instant;

pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub elapsed_ns: u128,
    pub ns_per_op: f64,
    pub ops_per_sec: f64,
}

pub fn bench_packet_normalization(iterations: u64) -> BenchmarkResult {
    let raw_event = BpfNetEvent {
        timestamp_ns: 123456789,
        src_ip: 0x0100007f, // 127.0.0.1
        dst_ip: 0x0500a8c0, // 192.168.0.5
        src_port: 443,
        dst_port: 54321,
        protocol: 6, // TCP
        action: 1,   // PASS
        pad: [0, 0],
        packet_len: 1500,
        ifindex: 2,
    };

    let node_id = NodeId(1);
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = std::hint::black_box(normalize_net_event(&raw_event, node_id));
    }
    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let ns_per_op = (elapsed_ns as f64) / (iterations as f64);
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    BenchmarkResult {
        name: "packet_event_normalization".to_string(),
        iterations,
        elapsed_ns,
        ns_per_op,
        ops_per_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_benchmark_executes() {
        let result = bench_packet_normalization(100);
        assert_eq!(result.iterations, 100);
        assert!(result.ns_per_op > 0.0);
    }
}
