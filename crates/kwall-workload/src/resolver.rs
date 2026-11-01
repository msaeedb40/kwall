//! Process-to-container workload resolver.

use kwall_core::error::{KwallError, Result};
use kwall_core::types::ProcessId;
use std::fs;
use std::path::Path;

use crate::cgroup::{parse_cgroup_path, CgroupContext};

/// Resolves a host PID to its Kubernetes cgroup context.
pub fn resolve_pid_cgroup(pid: ProcessId) -> Result<CgroupContext> {
    let cgroup_file = format!("/proc/{}/cgroup", pid.0);
    if !Path::new(&cgroup_file).exists() {
        return Err(KwallError::Internal(format!(
            "Process {pid} no longer exists"
        )));
    }

    let content = fs::read_to_string(&cgroup_file)
        .map_err(|e| KwallError::Internal(format!("Failed to read {cgroup_file}: {e}")))?;

    // On cgroups v2, line format is: 0::<path>
    // On cgroups v1, format is: <id>:<controller>:<path>
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            let path = parts[2];
            let ctx = parse_cgroup_path(path);
            if ctx.is_kubernetes || ctx.container_id.is_some() {
                return Ok(ctx);
            }
        }
    }

    // Default to the first line if not recognized as kubepods
    if let Some(first_line) = content.lines().next() {
        let parts: Vec<&str> = first_line.splitn(3, ':').collect();
        if parts.len() == 3 {
            return Ok(parse_cgroup_path(parts[2]));
        }
    }

    Ok(CgroupContext {
        raw_path: "".to_string(),
        pod_uid: None,
        container_id: None,
        is_kubernetes: false,
    })
}
