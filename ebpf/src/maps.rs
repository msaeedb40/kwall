//! Kernel-resident eBPF map definitions for KWALL.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf};
use kwall_ebpf_common::types::{FlowKey, PolicyMapValue};

/// Ingress CIDR lookup table (LPM Trie).
#[map(name = "KWALL_INGRESS_LPM")]
pub static KWALL_INGRESS_LPM: LpmTrie<[u8; 4], PolicyMapValue> = LpmTrie::with_max_entries(16384, 0);

/// Egress CIDR lookup table (LPM Trie).
#[map(name = "KWALL_EGRESS_LPM")]
pub static KWALL_EGRESS_LPM: LpmTrie<[u8; 4], PolicyMapValue> = LpmTrie::with_max_entries(16384, 0);

/// Connection flow tracking table (LRU Hash Map to bound memory).
#[map(name = "KWALL_FLOW_TABLE")]
pub static KWALL_FLOW_TABLE: LruHashMap<FlowKey, PolicyMapValue> = LruHashMap::with_max_entries(65536, 0);

/// Monitored and restricted process table.
#[map(name = "KWALL_PROCESS_MAP")]
pub static KWALL_PROCESS_MAP: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

/// High-throughput event delivery ring buffer.
#[map(name = "KWALL_RING_BUF")]
pub static KWALL_RING_BUF: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Per-CPU packet and event drop counters.
#[map(name = "KWALL_STATS")]
pub static KWALL_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);
