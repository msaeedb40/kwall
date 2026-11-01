//! # kwall-workload
//!
//! Linux cgroup parser, container runtime identifier resolution, and workload attribution.

pub mod cgroup;
pub mod resolver;

pub use cgroup::{parse_cgroup_path, CgroupContext};
pub use resolver::resolve_pid_cgroup;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_systemd_containerd_cgroup() {
        let path = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7b9c7b9c_1234_5678_9abc_def012345678.slice/cri-containerd-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2.scope";
        let ctx = parse_cgroup_path(path);

        assert!(ctx.is_kubernetes);
        assert_eq!(
            ctx.pod_uid.unwrap().as_str(),
            "7b9c7b9c-1234-5678-9abc-def012345678"
        );
        assert_eq!(
            ctx.container_id.unwrap().as_str(),
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );
    }

    #[test]
    fn test_parse_host_cgroup() {
        let path = "/user.slice/user-1000.slice/session-2.scope";
        let ctx = parse_cgroup_path(path);

        assert!(!ctx.is_kubernetes);
        assert!(ctx.pod_uid.is_none());
        assert!(ctx.container_id.is_none());
    }
}
