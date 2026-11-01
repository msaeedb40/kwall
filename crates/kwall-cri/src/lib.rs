//! # kwall-cri: Container Runtime Interface (CRI) Direct Integration
//!
//! Direct integration with local container runtimes (`containerd` & `CRI-O`) via UNIX domain
//! socket gRPC streaming. Eliminates Kubernetes Informer discovery latency and secures
//! container startups by pre-populating eBPF LSM maps before container processes are executed.
//!
//! ## Subsystems
//!
//! - **CRI v1 Client & Streamer (`client`)**: Connects to `/run/containerd/containerd.sock`
//!   and `/var/run/crio/crio.sock`, streaming real-time container lifecycle events.
//! - **OCI Bundle & Cgroup Resolver (`cgroup`)**: Resolves cgroup v1/v2 paths and OCI runtime
//!   specifications directly from bundle directories.
//! - **Pre-Execution LSM Synchronizer (`lsm_sync`)**: Pre-populates kernel eBPF LSM maps
//!   before `ContainerStarted` to eliminate the startup TOCTOU race condition.

pub mod cgroup;
pub mod client;
pub mod lsm_sync;

pub use cgroup::{
    OciBundleConfig, OciCgroupResolver, OciResolutionError, ResolvedContainerCgroupContext,
};
pub use client::{
    ContainerLifecycleEvent, ContainerLifecycleEventType, ContainerStatusInfo, CriClient,
    CriError, RuntimeType,
};
pub use lsm_sync::{
    LsmBinaryRestriction, LsmSyncError, PreExecutionLsmSynchronizer, PreExecutionSyncReceipt,
};

use std::sync::Arc;

/// Unified CRI Integration Manager coordinating streaming, cgroup attribution, and pre-exec LSM sync.
pub struct CriIntegrationManager {
    pub client: Arc<CriClient>,
    pub cgroup_resolver: Arc<OciCgroupResolver>,
    pub lsm_synchronizer: Arc<PreExecutionLsmSynchronizer>,
}

impl CriIntegrationManager {
    /// Constructs a manager with explicit runtime type and socket path.
    pub fn new(runtime_type: RuntimeType, socket_path: impl Into<std::path::PathBuf>) -> Result<Self, CriError> {
        let client = Arc::new(CriClient::new(runtime_type, socket_path)?);
        let cgroup_resolver = Arc::new(OciCgroupResolver::default());
        let lsm_synchronizer = Arc::new(PreExecutionLsmSynchronizer::default());

        Ok(Self {
            client,
            cgroup_resolver,
            lsm_synchronizer,
        })
    }

    /// Automatically discovers active container runtime on the host system.
    pub fn discover() -> Result<Self, CriError> {
        let client = Arc::new(CriClient::discover()?);
        let cgroup_resolver = Arc::new(OciCgroupResolver::default());
        let lsm_synchronizer = Arc::new(PreExecutionLsmSynchronizer::default());

        Ok(Self {
            client,
            cgroup_resolver,
            lsm_synchronizer,
        })
    }

    /// Processes an incoming container lifecycle event with pre-execution LSM enforcement.
    pub fn process_lifecycle_event(
        &self,
        event: ContainerLifecycleEvent,
        oci_config_json: Option<&str>,
        timestamp_ns: u64,
    ) -> Result<Option<PreExecutionSyncReceipt>, String> {
        let event_type = event.event_type;
        let container_id = event.container_id.clone();

        // 1. Ingest into client state
        self.client.ingest_event(event.clone());

        // 2. Pre-execution LSM synchronization on ContainerCreated
        match event_type {
            ContainerLifecycleEventType::Created => {
                if let Some(json) = oci_config_json {
                    let cgroup_ctx = self
                        .cgroup_resolver
                        .resolve_from_config_json(&container_id, json)
                        .map_err(|e| format!("OCI resolution failed: {e}"))?;

                    let receipt = self
                        .lsm_synchronizer
                        .synchronize_container(&event, &cgroup_ctx, timestamp_ns)
                        .map_err(|e| format!("LSM synchronization failed: {e}"))?;

                    return Ok(Some(receipt));
                }
            }
            ContainerLifecycleEventType::Deleted => {
                self.lsm_synchronizer.cleanup_container(&container_id);
            }
            _ => {}
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_cri_manager_end_to_end_pre_execution_containment() {
        let manager =
            CriIntegrationManager::new(RuntimeType::Containerd, "/tmp/mock_containerd.sock")
                .unwrap();

        let oci_config = r#"{
            "ociVersion": "1.0.2",
            "process": {
                "args": ["/app/webserver", "--port=80"]
            },
            "linux": {
                "cgroupsPath": "/kubepods/burstable/pod123/cnt456"
            },
            "annotations": {
                "io.kubernetes.pod.namespace": "ecommerce",
                "io.kubernetes.pod.name": "webserver-pod"
            }
        }"#;

        let created_event = ContainerLifecycleEvent {
            event_id: "evt-e2e-01".to_string(),
            container_id: "cnt456".to_string(),
            pod_sandbox_id: "sb-123".to_string(),
            pod_name: "webserver-pod".to_string(),
            pod_namespace: "ecommerce".to_string(),
            event_type: ContainerLifecycleEventType::Created,
            image: "kwall/web:v1".to_string(),
            timestamp_ns: 1_000_000,
            exit_code: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        // Process creation -> pre-populates LSM
        let receipt = manager
            .process_lifecycle_event(created_event, Some(oci_config), 1_000_000)
            .unwrap();

        assert!(receipt.is_some());
        let r = receipt.unwrap();
        assert_eq!(r.container_id, "cnt456");
        assert!(r.is_enforced_pre_exec);

        // Before container started, verify /bin/sh is blocked
        let action = manager
            .lsm_synchronizer
            .evaluate_execution(r.cgroup_id, "/bin/sh");
        assert_eq!(
            action,
            Some(kwall_policy::crd::RuntimePolicyAction::Deny)
        );

        // Container started event
        let started_event = ContainerLifecycleEvent {
            event_id: "evt-e2e-02".to_string(),
            container_id: "cnt456".to_string(),
            pod_sandbox_id: "sb-123".to_string(),
            pod_name: "webserver-pod".to_string(),
            pod_namespace: "ecommerce".to_string(),
            event_type: ContainerLifecycleEventType::Started,
            image: "kwall/web:v1".to_string(),
            timestamp_ns: 2_000_000,
            exit_code: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        manager
            .process_lifecycle_event(started_event, None, 2_000_000)
            .unwrap();

        let status = manager.client.get_container_status("cnt456").unwrap();
        assert_eq!(status.state, ContainerLifecycleEventType::Started);

        // Container deleted event -> cleans up
        let deleted_event = ContainerLifecycleEvent {
            event_id: "evt-e2e-03".to_string(),
            container_id: "cnt456".to_string(),
            pod_sandbox_id: "sb-123".to_string(),
            pod_name: "webserver-pod".to_string(),
            pod_namespace: "ecommerce".to_string(),
            event_type: ContainerLifecycleEventType::Deleted,
            image: "kwall/web:v1".to_string(),
            timestamp_ns: 5_000_000,
            exit_code: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        manager
            .process_lifecycle_event(deleted_event, None, 5_000_000)
            .unwrap();

        assert!(manager.client.get_container_status("cnt456").is_none());
        assert!(manager.lsm_synchronizer.get_receipt("cnt456").is_none());
    }
}
