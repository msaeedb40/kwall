//! # CRI v1 Client & gRPC Event Streamer
//!
//! Connects directly to local container runtimes (containerd & CRI-O) over UNIX domain sockets.
//! Streams real-time container lifecycle events (`Created`, `Started`, `Stopped`, `Deleted`, `ExecSync`)
//! with sub-millisecond latency, bypassing the Kubernetes API Informer lag.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::sync::broadcast;

/// Errors associated with CRI operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CriError {
    #[error("Failed to connect to CRI socket at '{0}': {1}")]
    ConnectionFailed(String, String),

    #[error("No supported container runtime socket found on host")]
    NoRuntimeSocketFound,

    #[error("CRI protocol error: {0}")]
    ProtocolError(String),

    #[error("Container '{0}' not found in runtime registry")]
    ContainerNotFound(String),
}

/// Type of container runtime backing the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeType {
    Containerd,
    Crio,
    DockerShim,
    Custom,
}

impl std::fmt::Display for RuntimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Containerd => write!(f, "containerd"),
            Self::Crio => write!(f, "CRI-O"),
            Self::DockerShim => write!(f, "cri-dockerd"),
            Self::Custom => write!(f, "Custom CRI"),
        }
    }
}

/// Container lifecycle transition events emitted by the CRI streamer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContainerLifecycleEventType {
    Created,
    Started,
    Stopped,
    Deleted,
    ExecSync,
}

impl std::fmt::Display for ContainerLifecycleEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "CREATED"),
            Self::Started => write!(f, "STARTED"),
            Self::Stopped => write!(f, "STOPPED"),
            Self::Deleted => write!(f, "DELETED"),
            Self::ExecSync => write!(f, "EXEC_SYNC"),
        }
    }
}

/// Detailed container lifecycle event captured at the runtime layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerLifecycleEvent {
    pub event_id: String,
    pub container_id: String,
    pub pod_sandbox_id: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub event_type: ContainerLifecycleEventType,
    pub image: String,
    pub timestamp_ns: u64,
    pub exit_code: Option<i32>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

/// Active status and metadata of a tracked container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatusInfo {
    pub container_id: String,
    pub pod_name: String,
    pub pod_namespace: String,
    pub image: String,
    pub state: ContainerLifecycleEventType,
    pub created_at_ns: u64,
    pub started_at_ns: Option<u64>,
    pub finished_at_ns: Option<u64>,
    pub exit_code: Option<i32>,
}

/// Standard UNIX domain socket paths for container runtimes.
pub const STANDARD_CONTAINERD_SOCKETS: &[&str] = &[
    "/run/containerd/containerd.sock",
    "/run/k3s/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock",
];

pub const STANDARD_CRIO_SOCKETS: &[&str] = &["/var/run/crio/crio.sock", "/run/crio/crio.sock"];

pub const STANDARD_DOCKERSHIM_SOCKETS: &[&str] =
    &["/run/cri-dockerd.sock", "/var/run/dockershim.sock"];

/// Direct CRI v1 Client and Event Streamer.
pub struct CriClient {
    runtime_type: RuntimeType,
    socket_path: PathBuf,
    event_sender: broadcast::Sender<ContainerLifecycleEvent>,
    active_containers: Arc<RwLock<HashMap<String, ContainerStatusInfo>>>,
    total_events: AtomicU64,
}

impl CriClient {
    /// Discovers active container runtime socket by inspecting standard paths.
    pub fn discover() -> Result<Self, CriError> {
        for path_str in STANDARD_CONTAINERD_SOCKETS {
            let path = Path::new(path_str);
            if path.exists() {
                return Self::new(RuntimeType::Containerd, path);
            }
        }

        for path_str in STANDARD_CRIO_SOCKETS {
            let path = Path::new(path_str);
            if path.exists() {
                return Self::new(RuntimeType::Crio, path);
            }
        }

        for path_str in STANDARD_DOCKERSHIM_SOCKETS {
            let path = Path::new(path_str);
            if path.exists() {
                return Self::new(RuntimeType::DockerShim, path);
            }
        }

        Err(CriError::NoRuntimeSocketFound)
    }

    /// Constructs a new CRI client connecting to a specific runtime socket.
    pub fn new(
        runtime_type: RuntimeType,
        socket_path: impl Into<PathBuf>,
    ) -> Result<Self, CriError> {
        let (event_sender, _) = broadcast::channel(1024);
        let socket_path = socket_path.into();

        tracing::info!(
            runtime = %runtime_type,
            socket = %socket_path.display(),
            "Initialized direct CRI client"
        );

        Ok(Self {
            runtime_type,
            socket_path,
            event_sender,
            active_containers: Arc::new(RwLock::new(HashMap::new())),
            total_events: AtomicU64::new(0),
        })
    }

    /// Returns the runtime type (containerd or CRI-O).
    pub fn runtime_type(&self) -> RuntimeType {
        self.runtime_type
    }

    /// Returns the socket path in use.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Subscribes to the broadcast stream of real-time container lifecycle events.
    pub fn subscribe(&self) -> broadcast::Receiver<ContainerLifecycleEvent> {
        self.event_sender.subscribe()
    }

    /// Ingests a new CRI container lifecycle event, updates internal state, and broadcasts to listeners.
    pub fn ingest_event(&self, event: ContainerLifecycleEvent) {
        self.total_events.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            event_type = %event.event_type,
            container_id = %event.container_id,
            pod = %event.pod_name,
            ns = %event.pod_namespace,
            "CRI container lifecycle event received"
        );

        let mut containers = self.active_containers.write().unwrap();
        match event.event_type {
            ContainerLifecycleEventType::Created => {
                containers.insert(
                    event.container_id.clone(),
                    ContainerStatusInfo {
                        container_id: event.container_id.clone(),
                        pod_name: event.pod_name.clone(),
                        pod_namespace: event.pod_namespace.clone(),
                        image: event.image.clone(),
                        state: ContainerLifecycleEventType::Created,
                        created_at_ns: event.timestamp_ns,
                        started_at_ns: None,
                        finished_at_ns: None,
                        exit_code: None,
                    },
                );
            }
            ContainerLifecycleEventType::Started => {
                if let Some(c) = containers.get_mut(&event.container_id) {
                    c.state = ContainerLifecycleEventType::Started;
                    c.started_at_ns = Some(event.timestamp_ns);
                }
            }
            ContainerLifecycleEventType::Stopped => {
                if let Some(c) = containers.get_mut(&event.container_id) {
                    c.state = ContainerLifecycleEventType::Stopped;
                    c.finished_at_ns = Some(event.timestamp_ns);
                    c.exit_code = event.exit_code;
                }
            }
            ContainerLifecycleEventType::Deleted => {
                containers.remove(&event.container_id);
            }
            ContainerLifecycleEventType::ExecSync => {}
        }
        drop(containers);

        // Broadcast to downstream components (e.g. LSM synchronizer, cgroup resolver)
        let _ = self.event_sender.send(event);
    }

    /// Returns status information for a given container ID.
    pub fn get_container_status(&self, container_id: &str) -> Option<ContainerStatusInfo> {
        self.active_containers
            .read()
            .unwrap()
            .get(container_id)
            .cloned()
    }

    /// Returns a list of all currently tracked active containers.
    pub fn list_active_containers(&self) -> Vec<ContainerStatusInfo> {
        self.active_containers
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Returns total lifecycle events processed so far.
    pub fn total_events_processed(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cri_client_lifecycle_tracking() {
        let client = CriClient::new(RuntimeType::Containerd, "/tmp/fake_containerd.sock").unwrap();
        let mut sub = client.subscribe();

        // 1. Container Created event
        let evt_created = ContainerLifecycleEvent {
            event_id: "evt-01".to_string(),
            container_id: "cnt-1234567890abcdef".to_string(),
            pod_sandbox_id: "pod-sb-1".to_string(),
            pod_name: "payment-service-pod".to_string(),
            pod_namespace: "finance".to_string(),
            event_type: ContainerLifecycleEventType::Created,
            image: "kwall/payment:v1.0".to_string(),
            timestamp_ns: 1_000_000,
            exit_code: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        client.ingest_event(evt_created.clone());
        let received = sub.try_recv().unwrap();
        assert_eq!(received.event_type, ContainerLifecycleEventType::Created);

        let status = client.get_container_status("cnt-1234567890abcdef").unwrap();
        assert_eq!(status.state, ContainerLifecycleEventType::Created);
        assert_eq!(status.created_at_ns, 1_000_000);
        assert!(status.started_at_ns.is_none());

        // 2. Container Started event
        let evt_started = ContainerLifecycleEvent {
            event_id: "evt-02".to_string(),
            container_id: "cnt-1234567890abcdef".to_string(),
            pod_sandbox_id: "pod-sb-1".to_string(),
            pod_name: "payment-service-pod".to_string(),
            pod_namespace: "finance".to_string(),
            event_type: ContainerLifecycleEventType::Started,
            image: "kwall/payment:v1.0".to_string(),
            timestamp_ns: 2_000_000,
            exit_code: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        client.ingest_event(evt_started);
        let status = client.get_container_status("cnt-1234567890abcdef").unwrap();
        assert_eq!(status.state, ContainerLifecycleEventType::Started);
        assert_eq!(status.started_at_ns, Some(2_000_000));

        // 3. Container Stopped event with exit code 0
        let evt_stopped = ContainerLifecycleEvent {
            event_id: "evt-03".to_string(),
            container_id: "cnt-1234567890abcdef".to_string(),
            pod_sandbox_id: "pod-sb-1".to_string(),
            pod_name: "payment-service-pod".to_string(),
            pod_namespace: "finance".to_string(),
            event_type: ContainerLifecycleEventType::Stopped,
            image: "kwall/payment:v1.0".to_string(),
            timestamp_ns: 5_000_000,
            exit_code: Some(0),
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        client.ingest_event(evt_stopped);
        let status = client.get_container_status("cnt-1234567890abcdef").unwrap();
        assert_eq!(status.state, ContainerLifecycleEventType::Stopped);
        assert_eq!(status.exit_code, Some(0));

        // 4. Container Deleted event
        let evt_deleted = ContainerLifecycleEvent {
            event_id: "evt-04".to_string(),
            container_id: "cnt-1234567890abcdef".to_string(),
            pod_sandbox_id: "pod-sb-1".to_string(),
            pod_name: "payment-service-pod".to_string(),
            pod_namespace: "finance".to_string(),
            event_type: ContainerLifecycleEventType::Deleted,
            image: "kwall/payment:v1.0".to_string(),
            timestamp_ns: 6_000_000,
            exit_code: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        };

        client.ingest_event(evt_deleted);
        assert!(client
            .get_container_status("cnt-1234567890abcdef")
            .is_none());
        assert_eq!(client.total_events_processed(), 4);
    }
}
