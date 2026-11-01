//! Live forensic memory snapshot and host process state acquisition.
//!
//! Gathers open file descriptors, active TCP sockets, process memory mappings,
//! and resource utilization for compromised container environments.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Comprehensive forensic artifact bundle captured during an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvidenceBundle {
    pub bundle_id: String,
    pub workload_id: String,
    pub timestamp_ns: u64,
    pub target_pid: u32,
    pub open_file_descriptors: Vec<String>,
    pub network_sockets: Vec<String>,
    pub memory_maps_snippet: Vec<String>,
    pub cgroup_stats: HashMap<String, String>,
    pub pcap_bytes_len: usize,
    pub pcap_base64: Option<String>,
}

/// Forensic snapshot manager capturing runtime evidence from `/proc` and cgroups.
pub struct ForensicSnapshotManager;

impl ForensicSnapshotManager {
    /// Captures a live forensic snapshot for a specified target process and workload.
    pub fn capture_snapshot(
        workload_id: &str,
        pid: u32,
        pcap_data: Option<&[u8]>,
    ) -> ForensicEvidenceBundle {
        let now = kwall_common::utilities::current_timestamp_ns();
        let bundle_id = format!("bundle-{}-{}", workload_id, now);

        let proc_path = format!("/proc/{}", pid);
        let pid_dir = Path::new(&proc_path);

        // 1. Gather open file descriptors
        let mut open_file_descriptors = Vec::new();
        if let Ok(entries) = fs::read_dir(pid_dir.join("fd")) {
            for entry in entries.flatten() {
                if let Ok(target) = fs::read_link(entry.path()) {
                    open_file_descriptors.push(target.to_string_lossy().to_string());
                }
            }
        }

        // 2. Gather active network sockets from /proc/[pid]/net/tcp
        let mut network_sockets = Vec::new();
        if let Ok(content) = fs::read_to_string(pid_dir.join("net/tcp")) {
            for line in content.lines().skip(1).take(20) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    network_sockets.push(format!(
                        "local:{} rem:{} state:{}",
                        parts[1], parts[2], parts[3]
                    ));
                }
            }
        }

        // 3. Gather memory maps snippet
        let mut memory_maps_snippet = Vec::new();
        if let Ok(content) = fs::read_to_string(pid_dir.join("maps")) {
            for line in content.lines().take(30) {
                memory_maps_snippet.push(line.to_string());
            }
        }

        // 4. Gather cgroup metrics if available
        let mut cgroup_stats = HashMap::new();
        if let Ok(cgroup_str) = fs::read_to_string(pid_dir.join("cgroup")) {
            cgroup_stats.insert(
                "cgroup_membership".to_string(),
                cgroup_str.trim().to_string(),
            );
        }

        let (pcap_bytes_len, pcap_base64) = match pcap_data {
            Some(bytes) if !bytes.is_empty() => {
                // Convert bytes to hex string for portable JSON serialization
                let mut hex_str = String::with_capacity(bytes.len() * 2);
                for b in bytes {
                    use std::fmt::Write;
                    let _ = write!(hex_str, "{b:02x}");
                }
                (bytes.len(), Some(hex_str))
            }
            _ => (0, None),
        };

        ForensicEvidenceBundle {
            bundle_id,
            workload_id: workload_id.to_string(),
            timestamp_ns: now,
            target_pid: pid,
            open_file_descriptors,
            network_sockets,
            memory_maps_snippet,
            cgroup_stats,
            pcap_bytes_len,
            pcap_base64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_self_snapshot() {
        let current_pid = std::process::id();
        let fake_pcap = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let bundle = ForensicSnapshotManager::capture_snapshot(
            "test-workload-1",
            current_pid,
            Some(&fake_pcap),
        );

        assert_eq!(bundle.workload_id, "test-workload-1");
        assert_eq!(bundle.target_pid, current_pid);
        assert_eq!(bundle.pcap_bytes_len, 4);
        assert_eq!(bundle.pcap_base64.as_deref(), Some("deadbeef"));
    }
}
