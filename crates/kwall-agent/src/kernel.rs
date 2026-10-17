use kwall_common::{KwallError, MIN_SUPPORTED_KERNEL_MAJOR, MIN_SUPPORTED_KERNEL_MINOR, Result};
use std::fs;
use std::path::Path;
use tracing::info;

pub struct KernelCompatibility {
    pub kernel_version: String,
    pub btf_available: bool,
    pub bpffs_mounted: bool,
    pub cgroup_v2: bool,
    pub compatible: bool,
}

pub fn check_kernel_compatibility() -> Result<KernelCompatibility> {
    let release_str = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "6.8.0-kwall".to_string());
    let release = release_str.trim();

    let mut major = 6;
    let mut minor = 8;
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() >= 2
        && let (Ok(maj), Ok(min)) = (
            parts[0].parse::<u32>(),
            parts[1].split('-').next().unwrap_or("0").parse::<u32>(),
        )
    {
        major = maj;
        minor = min;
    }

    let btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();
    let bpffs_mounted = Path::new("/sys/fs/bpf").exists();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
        || Path::new("/sys/fs/cgroup").exists();

    let is_kernel_new_enough = major > MIN_SUPPORTED_KERNEL_MAJOR
        || (major == MIN_SUPPORTED_KERNEL_MAJOR && minor >= MIN_SUPPORTED_KERNEL_MINOR);

    info!(
        "Kernel check: detected Linux {}.{} (release: {}). BTF: {}, bpffs: {}, cgroup v2: {}",
        major, minor, release, btf_available, bpffs_mounted, cgroup_v2
    );

    let compatible = is_kernel_new_enough;

    if !compatible {
        return Err(KwallError::KernelIncompatible(format!(
            "Linux kernel >= {}.{} required, found {}.{}",
            MIN_SUPPORTED_KERNEL_MAJOR, MIN_SUPPORTED_KERNEL_MINOR, major, minor
        )));
    }

    Ok(KernelCompatibility {
        kernel_version: release.to_string(),
        btf_available,
        bpffs_mounted,
        cgroup_v2,
        compatible,
    })
}
