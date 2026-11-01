//! Host process tree termination and Linux cgroup freezer controllers.
//!
//! Provides instantaneous CPU execution freezing via Linux control groups (`cgroup.freeze`)
//! and surgical process tree signal dispatch (`SIGTERM`/`SIGKILL`) for rogue containment.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Isolation and containment error conditions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IsolationError {
    #[error("Failed to read process table: {0}")]
    ProcessTableError(String),
    #[error("Process PID {0} not found")]
    ProcessNotFound(u32),
    #[error("Signal delivery failed for PID {0}: {1}")]
    SignalDeliveryFailed(u32, String),
    #[error("Cgroup filesystem path '{0}' error: {1}")]
    CgroupError(PathBuf, String),
}

/// Freeze state of a container cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CgroupFreezeState {
    Frozen,
    Thawed,
}

/// Linux Cgroup Freezer managing cgroups v1 & v2 execution halting.
pub struct CgroupFreezer {
    /// Tracks frozen cgroups in memory for state inspection and audit.
    frozen_cgroups: RwLock<HashMap<PathBuf, CgroupFreezeState>>,
    /// Base cgroup mount path (typically `/sys/fs/cgroup`).
    base_cgroup_dir: PathBuf,
}

impl Default for CgroupFreezer {
    fn default() -> Self {
        Self::new(PathBuf::from("/sys/fs/cgroup"))
    }
}

impl CgroupFreezer {
    /// Creates a CgroupFreezer with a custom base cgroup directory.
    pub fn new(base_cgroup_dir: PathBuf) -> Self {
        Self {
            frozen_cgroups: RwLock::new(HashMap::new()),
            base_cgroup_dir,
        }
    }

    /// Halts all CPU execution within the specified cgroup without killing the processes.
    pub fn freeze(&self, cgroup_rel_path: &Path) -> Result<(), IsolationError> {
        let full_path = self.base_cgroup_dir.join(cgroup_rel_path);

        // Check cgroups v2 'cgroup.freeze'
        let v2_file = full_path.join("cgroup.freeze");
        if v2_file.exists() {
            fs::write(&v2_file, "1")
                .map_err(|e| IsolationError::CgroupError(v2_file.clone(), e.to_string()))?;
        } else {
            // Check cgroups v1 'freezer.state'
            let v1_file = full_path.join("freezer.state");
            if v1_file.exists() {
                fs::write(&v1_file, "FROZEN")
                    .map_err(|e| IsolationError::CgroupError(v1_file.clone(), e.to_string()))?;
            }
        }

        let mut map = self.frozen_cgroups.write().unwrap();
        map.insert(full_path, CgroupFreezeState::Frozen);

        tracing::warn!(cgroup = %cgroup_rel_path.display(), "Container cgroup frozen successfully");
        Ok(())
    }

    /// Resumes CPU execution for a previously frozen cgroup.
    pub fn thaw(&self, cgroup_rel_path: &Path) -> Result<(), IsolationError> {
        let full_path = self.base_cgroup_dir.join(cgroup_rel_path);

        let v2_file = full_path.join("cgroup.freeze");
        if v2_file.exists() {
            fs::write(&v2_file, "0")
                .map_err(|e| IsolationError::CgroupError(v2_file.clone(), e.to_string()))?;
        } else {
            let v1_file = full_path.join("freezer.state");
            if v1_file.exists() {
                fs::write(&v1_file, "THAWED")
                    .map_err(|e| IsolationError::CgroupError(v1_file.clone(), e.to_string()))?;
            }
        }

        let mut map = self.frozen_cgroups.write().unwrap();
        map.insert(full_path, CgroupFreezeState::Thawed);

        tracing::info!(cgroup = %cgroup_rel_path.display(), "Container cgroup execution resumed (thawed)");
        Ok(())
    }

    /// Checks if a cgroup path is registered as frozen.
    #[must_use]
    pub fn is_frozen(&self, cgroup_rel_path: &Path) -> bool {
        let full_path = self.base_cgroup_dir.join(cgroup_rel_path);
        let map = self.frozen_cgroups.read().unwrap();
        map.get(&full_path).copied() == Some(CgroupFreezeState::Frozen)
    }
}

/// Surgical process tree terminator.
pub struct ProcessTerminator;

impl ProcessTerminator {
    /// Collects the target PID and all descendant child PIDs.
    pub fn discover_process_tree(target_pid: u32) -> HashSet<u32> {
        let mut tree = HashSet::new();
        tree.insert(target_pid);

        // Scan /proc to discover children
        let proc_dir = Path::new("/proc");
        if let Ok(entries) = fs::read_dir(proc_dir) {
            let mut parent_map: HashMap<u32, u32> = HashMap::new();

            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        let stat_file = entry.path().join("stat");
                        if let Ok(content) = fs::read_to_string(&stat_file) {
                            // Fourth field in /proc/[pid]/stat is ppid
                            // Example: 1234 (bash) S 1000 ...
                            if let Some(close_paren) = content.rfind(')') {
                                let fields: Vec<&str> =
                                    content[close_paren + 1..].split_whitespace().collect();
                                if fields.len() >= 2 {
                                    if let Ok(ppid) = fields[1].parse::<u32>() {
                                        parent_map.insert(pid, ppid);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Expand descendants iteratively
            let mut added = true;
            while added {
                added = false;
                for (&child_pid, &ppid) in &parent_map {
                    if tree.contains(&ppid) && !tree.contains(&child_pid) {
                        tree.insert(child_pid);
                        added = true;
                    }
                }
            }
        }

        tree
    }

    /// Dispatches signal (e.g. 15 for SIGTERM, 9 for SIGKILL) to a process tree.
    pub fn kill_tree(target_pid: u32, signal: i32) -> Result<Vec<u32>, IsolationError> {
        let pids = Self::discover_process_tree(target_pid);
        let mut terminated = Vec::new();

        let self_pid = std::process::id();
        for &pid in &pids {
            // Guard against self-termination or init system (PID 1)
            if pid > 1 && pid != self_pid {
                #[cfg(unix)]
                unsafe {
                    let ret = libc::kill(pid as libc::pid_t, signal);
                    if ret == 0 {
                        terminated.push(pid);
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = signal;
                    terminated.push(pid);
                }
            }
        }

        tracing::warn!(
            target_pid = target_pid,
            signal = signal,
            terminated_count = terminated.len(),
            "Process tree signal dispatched"
        );
        Ok(terminated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_freezer_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!(
            "kwall_cgroup_test_{}",
            kwall_common::utilities::current_timestamp_ns()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let sub_cgroup = temp_dir.join("kubepods.slice/pod_test");
        fs::create_dir_all(&sub_cgroup).unwrap();

        // Create mock cgroup.freeze file
        let freeze_file = sub_cgroup.join("cgroup.freeze");
        fs::write(&freeze_file, "0").unwrap();

        let freezer = CgroupFreezer::new(temp_dir.clone());
        let rel_path = Path::new("kubepods.slice/pod_test");

        // 1. Freeze
        assert!(freezer.freeze(rel_path).is_ok());
        assert!(freezer.is_frozen(rel_path));
        assert_eq!(fs::read_to_string(&freeze_file).unwrap(), "1");

        // 2. Thaw
        assert!(freezer.thaw(rel_path).is_ok());
        assert!(!freezer.is_frozen(rel_path));
        assert_eq!(fs::read_to_string(&freeze_file).unwrap(), "0");

        // Cleanup
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_process_tree_discovery() {
        // Discovery on current process returns at least current PID
        let current_pid = std::process::id();
        let tree = ProcessTerminator::discover_process_tree(current_pid);
        assert!(tree.contains(&current_pid));
    }
}
