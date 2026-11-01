//! Node environment and kernel capability inspector.

use kwall_core::error::Result;
use std::path::Path;
use tracing::{info, warn};

/// System environment diagnostics report.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KernelReport {
    pub kernel_release: String,
    pub btf_available: bool,
    pub bpf_fs_mounted: bool,
    pub cgroup_v2_available: bool,
}

/// Inspects host environment for eBPF and runtime security prerequisites.
pub fn inspect_host_environment() -> Result<KernelReport> {
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();
    let bpf_fs_mounted = Path::new("/sys/fs/bpf").exists();
    let cgroup_v2_available = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    info!(
        "Host Kernel: {} | BTF: {} | BPF FS: {} | Cgroup v2: {}",
        kernel_release, btf_available, bpf_fs_mounted, cgroup_v2_available
    );

    if !btf_available {
        warn!("BTF (/sys/kernel/btf/vmlinux) not found; CO-RE features may be restricted");
    }

    if !bpf_fs_mounted {
        warn!("/sys/fs/bpf is not mounted; BPF map pinning will be disabled");
    }

    Ok(KernelReport {
        kernel_release,
        btf_available,
        bpf_fs_mounted,
        cgroup_v2_available,
    })
}
