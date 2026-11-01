//! Cgroup path parser and container runtime identifier extractor.

use kwall_core::types::{ContainerId, PodUid};

/// Details extracted from a Linux cgroup path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupContext {
    pub raw_path: String,
    pub pod_uid: Option<PodUid>,
    pub container_id: Option<ContainerId>,
    pub is_kubernetes: bool,
}

/// Parses a cgroup path (v1 or v2) to detect if it belongs to a Kubernetes container.
pub fn parse_cgroup_path(path: &str) -> CgroupContext {
    let mut pod_uid = None;
    let mut container_id = None;
    let is_kubernetes = path.contains("kubepods");

    // Standard Kubernetes cgroup paths format:
    // .../kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<UID>.slice/cri-containerd-<CID>.scope
    // or .../kubepods/burstable/pod<UID>/<CID>
    for segment in path.split('/') {
        if segment.contains("pod") {
            // Extract pod UID
            let clean = segment
                .trim_end_matches(".slice")
                .trim_start_matches("kubepods-besteffort-")
                .trim_start_matches("kubepods-burstable-")
                .trim_start_matches("kubepods-")
                .trim_start_matches("pod");

            if !clean.is_empty() {
                // Pod UIDs with underscores formatted from hyphens: e.g. "a1b2_c3d4" -> "a1b2-c3d4"
                let normalized = clean.replace('_', "-");
                pod_uid = Some(PodUid::new(normalized));
            }
        }

        // Check for container runtime IDs
        if segment.contains("cri-containerd-")
            || segment.contains("docker-")
            || segment.contains("crio-")
        {
            let cid = segment
                .trim_end_matches(".scope")
                .trim_start_matches("cri-containerd-")
                .trim_start_matches("docker-")
                .trim_start_matches("crio-");

            if !cid.is_empty() {
                container_id = Some(ContainerId::new(cid));
            }
        } else if is_kubernetes
            && segment.len() == 64
            && segment.chars().all(|c| c.is_ascii_hexdigit())
        {
            // Raw 64-char hex container ID
            container_id = Some(ContainerId::new(segment));
        }
    }

    CgroupContext {
        raw_path: path.to_string(),
        pod_uid,
        container_id,
        is_kubernetes,
    }
}
