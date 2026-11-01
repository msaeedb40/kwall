//! Userspace interfaces for managing kernel BPF maps.

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{HashMap, Map, MapData, PerCpuArray};
use kwall_core::error::{KwallError, Result};
use kwall_ebpf_common::types::PolicyMapValue;

/// Userspace controller for KWALL BPF maps.
pub struct MapController {
    ingress_lpm: LpmTrie<MapData, [u8; 4], PolicyMapValue>,
    process_map: HashMap<MapData, u32, u32>,
    stats_map: PerCpuArray<MapData, u64>,
}

impl MapController {
    pub fn new(ingress_lpm_map: Map, process_map: Map, stats_map: Map) -> Result<Self> {
        let ingress_lpm = LpmTrie::try_from(ingress_lpm_map)
            .map_err(|e| KwallError::Ebpf(format!("Failed to open ingress LPM trie: {e}")))?;

        let process_map = HashMap::try_from(process_map)
            .map_err(|e| KwallError::Ebpf(format!("Failed to open process map: {e}")))?;

        let stats_map = PerCpuArray::try_from(stats_map)
            .map_err(|e| KwallError::Ebpf(format!("Failed to open stats map: {e}")))?;

        Ok(Self {
            ingress_lpm,
            process_map,
            stats_map,
        })
    }

    /// Inserts or updates an ingress IPv4 CIDR rule in the kernel LPM trie.
    pub fn set_ingress_rule(
        &mut self,
        ip_bytes: [u8; 4],
        prefix_len: u32,
        policy: PolicyMapValue,
    ) -> Result<()> {
        let key = Key::new(prefix_len, ip_bytes);
        self.ingress_lpm
            .insert(&key, &policy, 0)
            .map_err(|e| KwallError::Ebpf(format!("Failed to insert ingress LPM rule: {e}")))?;
        Ok(())
    }

    /// Adds a process PID to the restricted/blocked execution table.
    pub fn block_process(&mut self, pid: u32) -> Result<()> {
        self.process_map
            .insert(&pid, &1, 0)
            .map_err(|e| KwallError::Ebpf(format!("Failed to block process {pid}: {e}")))?;
        Ok(())
    }

    /// Unblocks a process PID from the restricted execution table.
    pub fn unblock_process(&mut self, pid: u32) -> Result<()> {
        let _ = self.process_map.remove(&pid);
        Ok(())
    }

    /// Reads aggregate packet counters across all CPU cores.
    pub fn read_stats(&self, index: u32) -> Result<u64> {
        let per_cpu_values = self
            .stats_map
            .get(&index, 0)
            .map_err(|e| KwallError::Ebpf(format!("Failed to read stats counter {index}: {e}")))?;

        let total: u64 = per_cpu_values.iter().sum();
        Ok(total)
    }
}
