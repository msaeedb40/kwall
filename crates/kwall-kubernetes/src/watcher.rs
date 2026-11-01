//! Kubernetes API resource watchers and informer synchronization.

use k8s_openapi::api::core::v1::Pod;
use kwall_core::types::{ContainerId, PodUid};
use std::sync::Arc;
use tracing::debug;

use crate::cache::{KubernetesCache, PodMetadata};

/// Extracts PodMetadata from a Kubernetes Pod resource.
pub fn extract_pod_metadata(pod: &Pod) -> Option<PodMetadata> {
    let metadata = &pod.metadata;
    let uid_str = metadata.uid.as_ref()?;
    let name = metadata.name.as_ref()?.clone();
    let namespace = metadata
        .namespace
        .as_deref()
        .unwrap_or("default")
        .to_string();

    let node_name = pod
        .spec
        .as_ref()
        .and_then(|s| s.node_name.clone())
        .unwrap_or_default();
    let service_account = pod
        .spec
        .as_ref()
        .and_then(|s| s.service_account_name.clone())
        .unwrap_or_else(|| "default".to_string());

    let status = pod.status.as_ref();
    let pod_ip = status.and_then(|s| s.pod_ip.clone());
    let host_ip = status.and_then(|s| s.host_ip.clone());

    let mut container_ids = Vec::new();
    if let Some(statuses) = status.and_then(|s| s.container_statuses.as_ref()) {
        for cs in statuses {
            if let Some(ref cid) = cs.container_id {
                let trimmed = cid
                    .strip_prefix("containerd://")
                    .or_else(|| cid.strip_prefix("docker://"))
                    .or_else(|| cid.strip_prefix("cri-o://"))
                    .unwrap_or(cid);
                container_ids.push(ContainerId::new(trimmed));
            }
        }
    }

    let labels = metadata
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let workload_owner = metadata
        .owner_references
        .as_ref()
        .and_then(|owners| owners.first().map(|o| format!("{}/{}", o.kind, o.name)));

    Some(PodMetadata {
        pod_uid: PodUid::new(uid_str),
        pod_name: name,
        namespace,
        node_name,
        service_account,
        pod_ip,
        host_ip,
        labels,
        workload_owner,
        container_ids,
    })
}

/// Applies a pod event to update the in-memory cache.
pub fn update_cache_from_pod(cache: &Arc<KubernetesCache>, pod: &Pod) {
    if let Some(meta) = extract_pod_metadata(pod) {
        debug!(pod_name = %meta.pod_name, namespace = %meta.namespace, "Indexing pod");
        cache.insert_pod(meta);
    }
}
