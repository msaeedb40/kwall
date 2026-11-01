//! # Multi-Cluster Global Control Plane & Telemetry Aggregator
//!
//! Provides centralized management for multi-region and multi-cloud Kubernetes clusters
//! (AWS EKS, GCP GKE, Azure AKS, KinD, BareMetal). Tracks cluster health, heartbeat monitoring,
//! and aggregates security events and service topology into a unified pane of glass.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Errors associated with multi-cluster control plane operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlPlaneError {
    #[error("Cluster '{0}' already registered")]
    ClusterAlreadyExists(String),

    #[error("Cluster '{0}' not found")]
    ClusterNotFound(String),

    #[error("Invalid cluster endpoint or configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Cluster '{0}' is disconnected or unreachable")]
    ClusterUnreachable(String),
}

/// Cloud provider hosting the Kubernetes cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CloudProvider {
    AwsEks,
    GcpGke,
    AzureAks,
    BareMetal,
    KindCluster,
    OpenShift,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsEks => write!(f, "AWS EKS"),
            Self::GcpGke => write!(f, "GCP GKE"),
            Self::AzureAks => write!(f, "Azure AKS"),
            Self::BareMetal => write!(f, "Bare Metal"),
            Self::KindCluster => write!(f, "KinD Cluster"),
            Self::OpenShift => write!(f, "Red Hat OpenShift"),
        }
    }
}

/// Health and connectivity status of a member cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterStatus {
    Connected,
    Degraded,
    Disconnected,
    Maintenance,
}

/// Metadata and state descriptor for a federated Kubernetes cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterDescriptor {
    pub cluster_id: String,
    pub name: String,
    pub provider: CloudProvider,
    pub region: String,
    pub api_endpoint: String,
    pub trust_domain: String,
    pub node_count: usize,
    pub agent_count: usize,
    pub status: ClusterStatus,
    pub last_heartbeat_timestamp_ns: u64,
    pub kwall_version: String,
    pub labels: HashMap<String, String>,
}

/// Cross-cluster security event reported from remote agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossClusterSecurityEvent {
    pub event_id: String,
    pub source_cluster: String,
    pub destination_cluster: String,
    pub source_spiffe: String,
    pub destination_spiffe: String,
    pub protocol: String,
    pub port: u16,
    pub action: String,
    pub timestamp_ns: u64,
    pub rule_id: u32,
}

/// Aggregated multi-cluster telemetry and security counters.
#[derive(Debug, Default)]
pub struct AggregatedTelemetryMetrics {
    pub total_clusters: AtomicU64,
    pub healthy_clusters: AtomicU64,
    pub total_nodes: AtomicU64,
    pub total_agents: AtomicU64,
    pub cross_cluster_flows: AtomicU64,
    pub cross_cluster_drops: AtomicU64,
    pub cross_cluster_alerts: AtomicU64,
}

/// Topology node in the multi-cluster service graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceGraphNode {
    pub cluster_id: String,
    pub namespace: String,
    pub service_name: String,
    pub spiffe_id: String,
}

/// Topology edge representing cross-cluster traffic flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceGraphEdge {
    pub source: ServiceGraphNode,
    pub destination: ServiceGraphNode,
    pub flow_count: u64,
    pub drop_count: u64,
    pub protocol: String,
    pub port: u16,
}

/// Centralized Global Control Plane managing cluster registry and heartbeat monitoring.
pub struct GlobalControlPlane {
    clusters: Arc<RwLock<HashMap<String, ClusterDescriptor>>>,
    heartbeat_timeout_ns: u64,
}

impl Default for GlobalControlPlane {
    fn default() -> Self {
        Self::new(60_000_000_000) // 60 seconds default heartbeat timeout
    }
}

impl GlobalControlPlane {
    /// Creates a new global control plane with the specified heartbeat timeout.
    pub fn new(heartbeat_timeout_ns: u64) -> Self {
        Self {
            clusters: Arc::new(RwLock::new(HashMap::new())),
            heartbeat_timeout_ns,
        }
    }

    /// Registers a new member cluster into the federation control plane.
    pub fn register_cluster(&self, descriptor: ClusterDescriptor) -> Result<(), ControlPlaneError> {
        let mut clusters = self.clusters.write().unwrap();
        if clusters.contains_key(&descriptor.cluster_id) {
            return Err(ControlPlaneError::ClusterAlreadyExists(
                descriptor.cluster_id,
            ));
        }

        tracing::info!(
            cluster_id = %descriptor.cluster_id,
            provider = %descriptor.provider,
            region = %descriptor.region,
            "Registered federated cluster"
        );
        clusters.insert(descriptor.cluster_id.clone(), descriptor);
        Ok(())
    }

    /// Deregisters an existing cluster from federation.
    pub fn deregister_cluster(
        &self,
        cluster_id: &str,
    ) -> Result<ClusterDescriptor, ControlPlaneError> {
        let mut clusters = self.clusters.write().unwrap();
        clusters
            .remove(cluster_id)
            .ok_or_else(|| ControlPlaneError::ClusterNotFound(cluster_id.to_string()))
    }

    /// Records an agent heartbeat from a member cluster.
    pub fn record_heartbeat(
        &self,
        cluster_id: &str,
        timestamp_ns: u64,
        node_count: usize,
        agent_count: usize,
    ) -> Result<(), ControlPlaneError> {
        let mut clusters = self.clusters.write().unwrap();
        let cluster = clusters
            .get_mut(cluster_id)
            .ok_or_else(|| ControlPlaneError::ClusterNotFound(cluster_id.to_string()))?;

        cluster.last_heartbeat_timestamp_ns = timestamp_ns;
        cluster.node_count = node_count;
        cluster.agent_count = agent_count;

        // Auto-recover status if it was previously disconnected or degraded
        if cluster.status == ClusterStatus::Disconnected
            || cluster.status == ClusterStatus::Degraded
        {
            cluster.status = ClusterStatus::Connected;
        }

        Ok(())
    }

    /// Returns a snapshot of a single cluster descriptor.
    pub fn get_cluster(&self, cluster_id: &str) -> Option<ClusterDescriptor> {
        self.clusters.read().unwrap().get(cluster_id).cloned()
    }

    /// Lists all registered clusters in the federation.
    pub fn list_clusters(&self) -> Vec<ClusterDescriptor> {
        self.clusters.read().unwrap().values().cloned().collect()
    }

    /// Evaluates cluster health statuses against current time and heartbeat timeout.
    pub fn evaluate_cluster_health(
        &self,
        current_timestamp_ns: u64,
    ) -> HashMap<String, ClusterStatus> {
        let mut clusters = self.clusters.write().unwrap();
        let mut health_map = HashMap::new();

        for (id, cluster) in clusters.iter_mut() {
            if cluster.status == ClusterStatus::Maintenance {
                health_map.insert(id.clone(), ClusterStatus::Maintenance);
                continue;
            }

            let elapsed = current_timestamp_ns.saturating_sub(cluster.last_heartbeat_timestamp_ns);
            if elapsed > self.heartbeat_timeout_ns * 2 {
                cluster.status = ClusterStatus::Disconnected;
            } else if elapsed > self.heartbeat_timeout_ns {
                cluster.status = ClusterStatus::Degraded;
            } else {
                cluster.status = ClusterStatus::Connected;
            }
            health_map.insert(id.clone(), cluster.status);
        }

        health_map
    }
}

/// Global Telemetry Aggregator providing a single pane of glass for security telemetry.
pub struct GlobalTelemetryAggregator {
    metrics: Arc<AggregatedTelemetryMetrics>,
    recent_events: Arc<RwLock<Vec<CrossClusterSecurityEvent>>>,
    service_graph_edges: Arc<RwLock<Vec<ServiceGraphEdge>>>,
    max_recent_events: usize,
}

impl Default for GlobalTelemetryAggregator {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl GlobalTelemetryAggregator {
    /// Creates a new telemetry aggregator with maximum event capacity.
    pub fn new(max_recent_events: usize) -> Self {
        Self {
            metrics: Arc::new(AggregatedTelemetryMetrics::default()),
            recent_events: Arc::new(RwLock::new(Vec::new())),
            service_graph_edges: Arc::new(RwLock::new(Vec::new())),
            max_recent_events,
        }
    }

    /// Records an inbound cross-cluster security event and updates metrics.
    pub fn record_event(&self, event: CrossClusterSecurityEvent) {
        self.metrics
            .cross_cluster_flows
            .fetch_add(1, Ordering::Relaxed);

        if event.action.eq_ignore_ascii_case("drop") || event.action.eq_ignore_ascii_case("deny") {
            self.metrics
                .cross_cluster_drops
                .fetch_add(1, Ordering::Relaxed);
            self.metrics
                .cross_cluster_alerts
                .fetch_add(1, Ordering::Relaxed);
        }

        let mut events = self.recent_events.write().unwrap();
        if events.len() >= self.max_recent_events {
            events.remove(0);
        }
        events.push(event);
    }

    /// Records a multi-cluster service communication edge in the topology graph.
    pub fn record_service_edge(&self, edge: ServiceGraphEdge) {
        let mut edges = self.service_graph_edges.write().unwrap();
        if let Some(existing) = edges.iter_mut().find(|e| {
            e.source.spiffe_id == edge.source.spiffe_id
                && e.destination.spiffe_id == edge.destination.spiffe_id
                && e.port == edge.port
        }) {
            existing.flow_count += edge.flow_count;
            existing.drop_count += edge.drop_count;
        } else {
            edges.push(edge);
        }
    }

    /// Returns the global service topology graph.
    pub fn get_service_graph(&self) -> Vec<ServiceGraphEdge> {
        self.service_graph_edges.read().unwrap().clone()
    }

    /// Returns a list of recent cross-cluster security events.
    pub fn get_recent_events(&self, limit: usize) -> Vec<CrossClusterSecurityEvent> {
        let events = self.recent_events.read().unwrap();
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Returns aggregated metrics summary.
    pub fn get_metrics_summary(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        map.insert(
            "cross_cluster_flows".to_string(),
            self.metrics.cross_cluster_flows.load(Ordering::Relaxed),
        );
        map.insert(
            "cross_cluster_drops".to_string(),
            self.metrics.cross_cluster_drops.load(Ordering::Relaxed),
        );
        map.insert(
            "cross_cluster_alerts".to_string(),
            self.metrics.cross_cluster_alerts.load(Ordering::Relaxed),
        );
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cluster(id: &str, provider: CloudProvider) -> ClusterDescriptor {
        ClusterDescriptor {
            cluster_id: id.to_string(),
            name: format!("Cluster {}", id),
            provider,
            region: "us-east-1".to_string(),
            api_endpoint: format!("https://{}.k8s.example.com", id),
            trust_domain: format!("{}.kwall.internal", id),
            node_count: 5,
            agent_count: 5,
            status: ClusterStatus::Connected,
            last_heartbeat_timestamp_ns: 1_000_000_000,
            kwall_version: "0.1.0".to_string(),
            labels: [("env".to_string(), "production".to_string())]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn test_cluster_registration_and_lookup() {
        let cp = GlobalControlPlane::default();
        let c1 = sample_cluster("c-aws-01", CloudProvider::AwsEks);
        let c2 = sample_cluster("c-gke-01", CloudProvider::GcpGke);

        assert!(cp.register_cluster(c1.clone()).is_ok());
        assert!(cp.register_cluster(c2.clone()).is_ok());

        // Duplicate registration should fail
        assert_eq!(
            cp.register_cluster(c1.clone()),
            Err(ControlPlaneError::ClusterAlreadyExists(
                "c-aws-01".to_string()
            ))
        );

        let retrieved = cp.get_cluster("c-aws-01").unwrap();
        assert_eq!(retrieved.provider, CloudProvider::AwsEks);
        assert_eq!(retrieved.region, "us-east-1");

        let all = cp.list_clusters();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_cluster_heartbeat_and_health_transition() {
        let timeout_ns = 10_000_000_000; // 10s
        let cp = GlobalControlPlane::new(timeout_ns);
        let c1 = sample_cluster("c-kind-01", CloudProvider::KindCluster);
        cp.register_cluster(c1).unwrap();

        // 5s elapsed -> Still Connected
        let health = cp.evaluate_cluster_health(1_000_000_000 + 5_000_000_000);
        assert_eq!(health["c-kind-01"], ClusterStatus::Connected);

        // 15s elapsed -> Degraded (>10s)
        let health = cp.evaluate_cluster_health(1_000_000_000 + 15_000_000_000);
        assert_eq!(health["c-kind-01"], ClusterStatus::Degraded);

        // 25s elapsed -> Disconnected (>20s)
        let health = cp.evaluate_cluster_health(1_000_000_000 + 25_000_000_000);
        assert_eq!(health["c-kind-01"], ClusterStatus::Disconnected);

        // Heartbeat arrives -> Recovers to Connected
        cp.record_heartbeat("c-kind-01", 1_000_000_000 + 26_000_000_000, 6, 6)
            .unwrap();
        let c = cp.get_cluster("c-kind-01").unwrap();
        assert_eq!(c.status, ClusterStatus::Connected);
        assert_eq!(c.node_count, 6);
    }

    #[test]
    fn test_telemetry_aggregator_events_and_service_graph() {
        let agg = GlobalTelemetryAggregator::default();

        let event = CrossClusterSecurityEvent {
            event_id: "evt-001".to_string(),
            source_cluster: "c-aws-01".to_string(),
            destination_cluster: "c-gke-01".to_string(),
            source_spiffe: "spiffe://c-aws-01.kwall.internal/ns/prod/sa/payment".to_string(),
            destination_spiffe: "spiffe://c-gke-01.kwall.internal/ns/prod/sa/ledger".to_string(),
            protocol: "TCP".to_string(),
            port: 443,
            action: "DROP".to_string(),
            timestamp_ns: 1_000_000,
            rule_id: 101,
        };

        agg.record_event(event);

        let metrics = agg.get_metrics_summary();
        assert_eq!(metrics["cross_cluster_flows"], 1);
        assert_eq!(metrics["cross_cluster_drops"], 1);
        assert_eq!(metrics["cross_cluster_alerts"], 1);

        let recent = agg.get_recent_events(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event_id, "evt-001");

        let edge = ServiceGraphEdge {
            source: ServiceGraphNode {
                cluster_id: "c-aws-01".to_string(),
                namespace: "prod".to_string(),
                service_name: "payment".to_string(),
                spiffe_id: "spiffe://c-aws-01.kwall.internal/ns/prod/sa/payment".to_string(),
            },
            destination: ServiceGraphNode {
                cluster_id: "c-gke-01".to_string(),
                namespace: "prod".to_string(),
                service_name: "ledger".to_string(),
                spiffe_id: "spiffe://c-gke-01.kwall.internal/ns/prod/sa/ledger".to_string(),
            },
            flow_count: 50,
            drop_count: 2,
            protocol: "TCP".to_string(),
            port: 443,
        };

        agg.record_service_edge(edge);
        let graph = agg.get_service_graph();
        assert_eq!(graph.len(), 1);
        assert_eq!(graph[0].flow_count, 50);
    }
}
