use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerCgroupInfo {
    pub pod_uid: Option<String>,
    pub container_id: Option<String>,
    pub is_kubernetes: bool,
}

pub fn parse_cgroup_path(path: &str) -> ContainerCgroupInfo {
    let mut pod_uid = None;
    let mut container_id = None;
    let mut is_kubernetes = false;

    if path.contains("kubepods") {
        is_kubernetes = true;
        // Search for pod<UID> pattern
        for part in path.split('/') {
            if let Some(sub) = part.split("-pod").nth(1) {
                // strip trailing slice/scope if present
                let uid = sub
                    .trim_end_matches(".slice")
                    .trim_end_matches(".scope")
                    .replace('_', "-");
                if !uid.is_empty() {
                    pod_uid = Some(uid);
                }
            }

            // Search for cri-containerd-<CID> or docker-<CID> or crio-<CID>
            if part.contains("cri-containerd-") || part.contains("docker-") || part.contains("crio-") {
                let cid = part
                    .replace("cri-containerd-", "")
                    .replace("docker-", "")
                    .replace("crio-", "")
                    .trim_end_matches(".scope")
                    .to_string();
                if !cid.is_empty() {
                    container_id = Some(cid);
                }
            }
        }
    }

    ContainerCgroupInfo {
        pod_uid,
        container_id,
        is_kubernetes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_path_parser() {
        let path = "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod3c9b74f0_8932_4719_a2cf_9b091f09e2cf.slice/cri-containerd-a1b2c3d4e5f6.scope";
        let info = parse_cgroup_path(path);
        assert!(info.is_kubernetes);
        assert_eq!(
            info.pod_uid.unwrap(),
            "3c9b74f0-8932-4719-a2cf-9b091f09e2cf"
        );
        assert_eq!(info.container_id.unwrap(), "a1b2c3d4e5f6");
    }
}
