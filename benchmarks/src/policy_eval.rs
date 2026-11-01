//! Benchmark suite for policy compilation and CIDR prefix indexing.

use crate::packet_parsing::BenchmarkResult;
use kwall_policy::compiler::compile_network_rule;
use kwall_policy::crd::network_policy::{NetworkPolicyAction, NetworkRule};
use std::time::Instant;

pub fn bench_policy_compilation(iterations: u64) -> BenchmarkResult {
    let rule = NetworkRule {
        cidr: "10.244.0.0/16".to_string(),
        port: Some(8080),
        protocol: Some("tcp".to_string()),
        action: NetworkPolicyAction::Allow,
    };

    let start = Instant::now();
    for i in 0..iterations {
        let _ = std::hint::black_box(compile_network_rule(&rule, i as u32));
    }
    let elapsed = start.elapsed();
    let elapsed_ns = elapsed.as_nanos();
    let ns_per_op = (elapsed_ns as f64) / (iterations as f64);
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    BenchmarkResult {
        name: "policy_rule_compilation".to_string(),
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
    fn test_policy_benchmark_executes() {
        let result = bench_policy_compilation(100);
        assert_eq!(result.iterations, 100);
    }
}
