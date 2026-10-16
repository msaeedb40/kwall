use serde::{Deserialize, Serialize};
use crate::constants::{DEFAULT_BPF_FS_PATH, DEFAULT_SOCKET_PATH, DEFAULT_METRICS_ADDR};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KwallConfig {
    #[serde(default = "default_bpf_fs")]
    pub bpf_fs_path: String,

    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,

    #[serde(default = "default_true")]
    pub enable_xdp: bool,

    #[serde(default = "default_true")]
    pub enable_tc: bool,

    #[serde(default = "default_true")]
    pub enable_lsm: bool,

    #[serde(default = "default_true")]
    pub enable_cgroup: bool,
}

fn default_bpf_fs() -> String {
    DEFAULT_BPF_FS_PATH.to_string()
}

fn default_socket_path() -> String {
    DEFAULT_SOCKET_PATH.to_string()
}

fn default_metrics_addr() -> String {
    DEFAULT_METRICS_ADDR.to_string()
}

fn default_true() -> bool {
    true
}

impl Default for KwallConfig {
    fn default() -> Self {
        Self {
            bpf_fs_path: default_bpf_fs(),
            socket_path: default_socket_path(),
            metrics_addr: default_metrics_addr(),
            enable_xdp: true,
            enable_tc: true,
            enable_lsm: true,
            enable_cgroup: true,
        }
    }
}
