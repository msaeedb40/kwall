//! # kwall-kubernetes
//!
//! Kubernetes API watchers, in-memory workload caches, and metadata indexers.

pub mod cache;
pub mod watcher;

pub use cache::{KubernetesCache, PodMetadata};
pub use watcher::{extract_pod_metadata, update_cache_from_pod};

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{ContainerId, PodUid};
    use std::collections::HashMap;

    #[test]
    fn test_cache_insertion_and_lookup() {
        let cache = KubernetesCache::new();

        let meta = PodMetadata {
            pod_uid: PodUid::new("uid-1234"),
            pod_name: "frontend-abc".to_string(),
            namespace: "prod".to_string(),
            node_name: "worker-node-1".to_string(),
            service_account: "frontend-sa".to_string(),
            pod_ip: Some("10.244.1.5".to_string()),
            host_ip: Some("192.168.1.100".to_string()),
            labels: HashMap::new(),
            workload_owner: Some("Deployment/frontend".to_string()),
            container_ids: vec![ContainerId::new("cid-999")],
        };

        cache.insert_pod(meta);
        assert_eq!(cache.len(), 1);

        // Lookup by IP
        let by_ip = cache.get_by_ip("10.244.1.5");
        assert!(by_ip.is_some());
        assert_eq!(by_ip.unwrap().pod_name, "frontend-abc");

        // Lookup by Container ID
        let by_cid = cache.get_by_container_id(&ContainerId::new("cid-999"));
        assert!(by_cid.is_some());
        assert_eq!(by_cid.unwrap().namespace, "prod");

        // Removal
        cache.remove_pod(&PodUid::new("uid-1234"));
        assert_eq!(cache.len(), 0);
        assert!(cache.get_by_ip("10.244.1.5").is_none());
    }
}
