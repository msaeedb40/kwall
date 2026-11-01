//! Benchmark suite for detection engine heuristic evaluations.

use crate::packet_parsing::BenchmarkResult;
use kwall_core::types::{CgroupId, EventSource, NodeId, ProcessId, Severity};
use kwall_detection::engine::DetectionEngine;
use kwall_event_enricher::enricher::EnrichedEvent;
use kwall_event_router::event::{EventPayload, KwallEvent, ProcessEventData};
use std::time::Instant;

pub fn bench_threat_detection_throughput(iterations: u64) -> BenchmarkResult {
    let engine = DetectionEngine::default();

    let event = EnrichedEvent {
        base_event: KwallEvent {
            version: 1,
            event_id: 1,
            timestamp_ns: 100,
            node_id: NodeId(1),
            severity: Severity::Notice,
            source: EventSource::TracepointProcess,
            payload: EventPayload::Process(ProcessEventData {
                pid: ProcessId(123),
                tgid: 123,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                cgroup_id: CgroupId(5),
                comm: "nginx".to_string(),
                filename: "/usr/sbin/nginx".to_string(),
            }),
        },
        src_workload: None,
        dst_workload: None,
    };

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = std::hint::black_box(engine.process_event(&event));
    }
    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let ns_per_op = (elapsed_ns as f64) / (iterations as f64);
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    BenchmarkResult {
        name: "detection_engine_event_evaluation".to_string(),
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
    fn test_detection_benchmark_executes() {
        let result = bench_threat_detection_throughput(100);
        assert_eq!(result.iterations, 100);
    }
}
