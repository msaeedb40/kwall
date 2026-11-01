//! In-memory cache indexing Kubernetes workloads by IP, Pod UID, and Container ID.

use kwall_core::types::{ContainerId, PodUid};
use std::collections::HashMap;
use std::sync::RwLock;

/// Comprehensive workload metadata discovered from Kubernetes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodMetadata {
    pub pod_uid: PodUid,
    pub pod_name: String,
    pub namespace: String,
    pub node_name: String,
    pub service_account: String,
    pub pod_ip: Option<String>,
    pub host_ip: Option<String>,
    pub labels: HashMap<String, String>,
    pub workload_owner: Option<String>,
    pub container_ids: Vec<ContainerId>,
}

/// Thread-safe in-memory cache for fast metadata lookup.
#[derive(Debug, Default)]
pub struct KubernetesCache {
    by_pod_ip: RwLock<HashMap<String, PodMetadata>>,
    by_pod_uid: RwLock<HashMap<PodUid, PodMetadata>>,
    by_container_id: RwLock<HashMap<ContainerId, PodMetadata>>,
}

impl KubernetesCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or updates pod metadata in the index.
    pub fn insert_pod(&self, pod: PodMetadata) {
        let mut by_uid = self.by_pod_uid.write().unwrap();
        let mut by_ip = self.by_pod_ip.write().unwrap();
        let mut by_cid = self.by_container_id.write().unwrap();

        if let Some(ref ip) = pod.pod_ip {
            by_ip.insert(ip.clone(), pod.clone());
        }

        for cid in &pod.container_ids {
            by_cid.insert(cid.clone(), pod.clone());
        }

        by_uid.insert(pod.pod_uid.clone(), pod);
    }

    /// Removes a pod from all internal indices when terminated.
    pub fn remove_pod(&self, pod_uid: &PodUid) {
        let mut by_uid = self.by_pod_uid.write().unwrap();
        if let Some(pod) = by_uid.remove(pod_uid) {
            let mut by_ip = self.by_pod_ip.write().unwrap();
            let mut by_cid = self.by_container_id.write().unwrap();

            if let Some(ref ip) = pod.pod_ip {
                by_ip.remove(ip);
            }

            for cid in &pod.container_ids {
                by_cid.remove(cid);
            }
        }
    }

    /// Lookup pod metadata by Pod IP address.
    pub fn get_by_ip(&self, ip: &str) -> Option<PodMetadata> {
        self.by_pod_ip.read().unwrap().get(ip).cloned()
    }

    /// Lookup pod metadata by Container ID.
    pub fn get_by_container_id(&self, container_id: &ContainerId) -> Option<PodMetadata> {
        self.by_container_id
            .read()
            .unwrap()
            .get(container_id)
            .cloned()
    }

    /// Total pods currently indexed.
    pub fn len(&self) -> usize {
        self.by_pod_uid.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
