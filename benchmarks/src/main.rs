//! KWALL Performance Benchmarking Suite.

pub mod packet_parsing;
pub mod policy_eval;
pub mod threat_detection;

use packet_parsing::{bench_packet_normalization, BenchmarkResult};
use policy_eval::bench_policy_compilation;
use threat_detection::bench_threat_detection_throughput;

fn print_result(res: &BenchmarkResult) {
    println!(
        "{:<35} | {:>10} ops | {:>10.2} ns/op | {:>10.2} Mops/sec",
        res.name,
        res.iterations,
        res.ns_per_op,
        res.ops_per_sec / 1_000_000.0
    );
}

fn main() {
    println!(
        "========================================================================================="
    );
    println!("KWALL Micro & Macro Performance Benchmarks");
    println!(
        "========================================================================================="
    );
    println!(
        "{:<35} | {:>14} | {:>16} | {:>19}",
        "Benchmark", "Iterations", "Latency", "Throughput"
    );
    println!(
        "-----------------------------------------------------------------------------------------"
    );

    let r1 = bench_packet_normalization(100_000);
    print_result(&r1);

    let r2 = bench_policy_compilation(100_000);
    print_result(&r2);

    let r3 = bench_threat_detection_throughput(50_000);
    print_result(&r3);

    println!(
        "========================================================================================="
    );
}
