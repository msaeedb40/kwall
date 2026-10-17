use crate::cgroup::{ContainerCgroupInfo, parse_cgroup_path};
use kwall_common::{KwallError, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub exe_path: Option<String>,
    pub exe_hash: Option<String>,
    pub cmdline: Vec<String>,
    pub cgroup_info: ContainerCgroupInfo,
    pub netns_inode: Option<u64>,
    pub mntns_inode: Option<u64>,
    pub pidns_inode: Option<u64>,
    pub is_suspicious_path: bool,
    pub container_escape_risk: bool,
}

pub struct ProcessInspector;

impl ProcessInspector {
    pub fn inspect_pid(pid: u32) -> Result<ProcessInfo> {
        let proc_dir = format!("/proc/{}", pid);
        if !Path::new(&proc_dir).exists() {
            return Err(KwallError::Runtime(format!(
                "Process {} does not exist",
                pid
            )));
        }

        // Read exe link
        let exe_path = fs::read_link(format!("{}/exe", proc_dir))
            .ok()
            .map(|p| p.to_string_lossy().to_string());

        // Calculate binary hash if accessible
        let exe_hash = exe_path.as_deref().and_then(|p| {
            fs::read(p)
                .ok()
                .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        });

        // Read cmdline
        let cmdline: Vec<String> = fs::read(format!("{}/cmdline", proc_dir))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|slice| !slice.is_empty())
            .map(|slice| String::from_utf8_lossy(slice).to_string())
            .collect();

        // Read cgroup
        let cgroup_str = fs::read_to_string(format!("{}/cgroup", proc_dir)).unwrap_or_default();
        let cgroup_info = parse_cgroup_path(&cgroup_str);

        // Read namespace inodes
        let netns_inode = Self::read_ns_inode(pid, "net");
        let mntns_inode = Self::read_ns_inode(pid, "mnt");
        let pidns_inode = Self::read_ns_inode(pid, "pid");

        // Parse uid & gid from status
        let (uid, gid) = Self::read_uid_gid(pid);

        // Check if executable path is suspicious (e.g. running out of /tmp, /dev/shm, or deleted memory file)
        let is_suspicious_path = exe_path.as_deref().is_some_and(|p| {
            p.starts_with("/tmp")
                || p.starts_with("/var/tmp")
                || p.starts_with("/dev/shm")
                || p.contains("(deleted)")
                || p.starts_with("/memfd:")
        });

        // Detect container escape risk: process is inside a container cgroup but sharing host mount or pid namespace
        let container_escape_risk = if cgroup_info.is_kubernetes {
            // Compare with PID 1's namespace if accessible
            let host_mntns = Self::read_ns_inode(1, "mnt");
            let host_pidns = Self::read_ns_inode(1, "pid");
            (host_mntns.is_some() && host_mntns == mntns_inode)
                || (host_pidns.is_some() && host_pidns == pidns_inode)
        } else {
            false
        };

        Ok(ProcessInfo {
            pid,
            uid,
            gid,
            exe_path,
            exe_hash,
            cmdline,
            cgroup_info,
            netns_inode,
            mntns_inode,
            pidns_inode,
            is_suspicious_path,
            container_escape_risk,
        })
    }

    fn read_ns_inode(pid: u32, ns_type: &str) -> Option<u64> {
        let link_target = fs::read_link(format!("/proc/{}/ns/{}", pid, ns_type)).ok()?;
        let target_str = link_target.to_string_lossy();
        // Link target format: "net:[4026532456]"
        if let Some(start) = target_str.find('[')
            && let Some(end) = target_str.find(']')
            && end > start + 1
        {
            return target_str[start + 1..end].parse::<u64>().ok();
        }
        None
    }

    fn read_uid_gid(pid: u32) -> (u32, u32) {
        let status_content =
            fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
        let mut uid = 0;
        let mut gid = 0;

        for line in status_content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    uid = parts[1].parse().unwrap_or(0);
                }
            } else if line.starts_with("Gid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    gid = parts[1].parse().unwrap_or(0);
                }
            }
        }

        (uid, gid)
    }
}
