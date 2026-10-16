use std::fs;
use std::path::Path;
use kwall_common::{KwallError, Result};
use serde::{Deserialize, Serialize};
use crate::cgroup::{parse_cgroup_path, ContainerCgroupInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe_path: Option<String>,
    pub cmdline: Vec<String>,
    pub cgroup_info: ContainerCgroupInfo,
}

pub struct ProcessInspector;

impl ProcessInspector {
    pub fn inspect_pid(pid: u32) -> Result<ProcessInfo> {
        let proc_dir = format!("/proc/{}", pid);
        if !Path::new(&proc_dir).exists() {
            return Err(KwallError::Runtime(format!("Process {} does not exist", pid)));
        }

        // Read exe link
        let exe_path = fs::read_link(format!("{}/exe", proc_dir))
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        // Read cmdline
        let cmdline = fs::read(format!("{}/cmdline", proc_dir))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|slice| !slice.is_empty())
            .map(|slice| String::from_utf8_lossy(slice).to_string())
            .collect();

        // Read cgroup
        let cgroup_str = fs::read_to_string(format!("{}/cgroup", proc_dir)).unwrap_or_default();
        let cgroup_info = parse_cgroup_path(&cgroup_str);

        Ok(ProcessInfo {
            pid,
            exe_path,
            cmdline,
            cgroup_info,
        })
    }
}
