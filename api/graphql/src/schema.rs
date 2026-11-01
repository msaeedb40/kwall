//! # Unified GraphQL & OpenAPI Gateway Schema
//!
//! Provides a hierarchical, async GraphQL API gateway for multi-cluster KWALL
//! security management.  The schema mirrors the KWALL domain model:
//!
//! ```graphql
//! query {
//!   clusters {
//!     id, name, provider, status
//!     nodes {
//!       id, hostname, ebpfReady, lsmSupported
//!       workloads {
//!         podName, namespace, riskScore, riskTier
//!         alerts { id, severity, category, mitreTactic }
//!         networkFlows { srcIp, dstIp, bytes, action }
//!       }
//!     }
//!     policies { id, name, kind, action, status }
//!   }
//! }
//! ```
//!
//! ## OpenAPI v3 REST surface
//!
//! Alongside the GraphQL endpoint (`/graphql`), a REST API is served under
//! `/api/v1/` for SIEM/SOAR integrations (Splunk, Elastic, QRadar, Sentinel).
//!
//! | Method | Path                             | Purpose                          |
//! |--------|----------------------------------|----------------------------------|
//! | GET    | `/api/v1/clusters`               | List all federated clusters      |
//! | GET    | `/api/v1/clusters/{id}/nodes`     | List nodes in a cluster          |
//! | GET    | `/api/v1/alerts`                 | Query active threat alerts       |
//! | GET    | `/api/v1/flows`                  | Query network flow records       |
//! | GET    | `/api/v1/policies`               | List security policies           |
//! | POST   | `/api/v1/policies/validate`      | Validate a policy YAML           |
//! | GET    | `/api/v1/compliance/{framework}` | Generate compliance report       |

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;

// ---------------------------------------------------------------------------
// GraphQL type system (mirrors KWALL domain model)
// ---------------------------------------------------------------------------

/// Kubernetes cluster provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterProvider {
    AwsEks,
    GcpGke,
    AzureAks,
    KinD,
    BareMetal,
    OpenShift,
}

impl std::fmt::Display for ClusterProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AwsEks => write!(f, "AWS EKS"),
            Self::GcpGke => write!(f, "GCP GKE"),
            Self::AzureAks => write!(f, "Azure AKS"),
            Self::KinD => write!(f, "KinD"),
            Self::BareMetal => write!(f, "BareMetal"),
            Self::OpenShift => write!(f, "OpenShift"),
        }
    }
}

/// Cluster connectivity status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterStatus {
    Connected,
    Degraded,
    Disconnected,
    Maintenance,
}

/// GraphQL: Cluster root type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlCluster {
    pub id: String,
    pub name: String,
    pub provider: ClusterProvider,
    pub region: String,
    pub status: ClusterStatus,
    pub kubernetes_version: String,
    pub node_count: u32,
    pub total_alerts: u64,
    pub total_policies: u32,
}

/// GraphQL: Node type within a cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlNode {
    pub id: String,
    pub hostname: String,
    pub cluster_id: String,
    pub ebpf_ready: bool,
    pub lsm_supported: bool,
    pub xdp_supported: bool,
    pub kernel_version: String,
    pub agent_version: String,
    pub workload_count: u32,
}

/// Alert severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    High,
    Critical,
}

/// GraphQL: Active threat alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlAlert {
    pub id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub namespace: String,
    pub workload: String,
    pub severity: AlertSeverity,
    pub category: String,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub description: String,
    pub timestamp_ns: u64,
    pub resolved: bool,
}

/// GraphQL: Workload risk profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlWorkload {
    pub pod_name: String,
    pub namespace: String,
    pub cluster_id: String,
    pub node_id: String,
    pub risk_score: f64,
    pub risk_tier: String,
    pub container_count: u32,
    pub alert_count: u32,
}

/// Network flow direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    Ingress,
    Egress,
}

/// GraphQL: Network flow record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlNetworkFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub direction: FlowDirection,
    pub bytes: u64,
    pub action: String,
    pub namespace: String,
    pub timestamp_ns: u64,
}

/// Policy enforcement action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
    Audit,
}

/// Policy kind discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyKind {
    KwallNetworkPolicy,
    KwallRuntimePolicy,
}

/// GraphQL: Security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GqlPolicy {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub cluster_id: String,
    pub kind: PolicyKind,
    pub action: PolicyAction,
    pub rule_count: u32,
    pub applied: bool,
}

// ---------------------------------------------------------------------------
// Query / filter types
// ---------------------------------------------------------------------------

/// Alert query filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertFilter {
    pub cluster_id: Option<String>,
    pub namespace: Option<String>,
    pub severity: Option<AlertSeverity>,
    pub resolved: Option<bool>,
    pub limit: Option<usize>,
}

/// Flow query filter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowFilter {
    pub cluster_id: Option<String>,
    pub namespace: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// GraphQL Gateway (in-memory resolver)
// ---------------------------------------------------------------------------

/// Runtime statistics for the gateway.
#[derive(Debug, Default)]
pub struct GatewayStats {
    pub queries_total: AtomicU64,
    pub mutations_total: AtomicU64,
    pub errors_total: AtomicU64,
}

impl GatewayStats {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.queries_total.load(Ordering::Relaxed),
            self.mutations_total.load(Ordering::Relaxed),
            self.errors_total.load(Ordering::Relaxed),
        )
    }
}

/// In-memory GraphQL/REST API gateway resolving queries against KWALL's domain state.
///
/// In production this would use `async-graphql` with subscriptions over WebSocket.
/// Here we implement the resolver logic that the gateway framework would delegate to.
pub struct GraphQLGateway {
    clusters: RwLock<Vec<GqlCluster>>,
    nodes: RwLock<Vec<GqlNode>>,
    alerts: RwLock<Vec<GqlAlert>>,
    workloads: RwLock<Vec<GqlWorkload>>,
    flows: RwLock<Vec<GqlNetworkFlow>>,
    policies: RwLock<Vec<GqlPolicy>>,
    stats: Arc<GatewayStats>,
}

impl Default for GraphQLGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphQLGateway {
    pub fn new() -> Self {
        info!("GraphQL & OpenAPI gateway initialised");
        Self {
            clusters: RwLock::new(Vec::new()),
            nodes: RwLock::new(Vec::new()),
            alerts: RwLock::new(Vec::new()),
            workloads: RwLock::new(Vec::new()),
            flows: RwLock::new(Vec::new()),
            policies: RwLock::new(Vec::new()),
            stats: Arc::new(GatewayStats::default()),
        }
    }

    pub fn stats(&self) -> Arc<GatewayStats> {
        Arc::clone(&self.stats)
    }

    // ---------------------------------------------------------------
    // Data ingestion (from KWALL subsystems → gateway state)
    // ---------------------------------------------------------------

    pub fn register_cluster(&self, cluster: GqlCluster) {
        self.clusters.write().unwrap().push(cluster);
    }

    pub fn register_node(&self, node: GqlNode) {
        self.nodes.write().unwrap().push(node);
    }

    pub fn ingest_alert(&self, alert: GqlAlert) {
        self.alerts.write().unwrap().push(alert);
    }

    pub fn ingest_workload(&self, workload: GqlWorkload) {
        self.workloads.write().unwrap().push(workload);
    }

    pub fn ingest_flow(&self, flow: GqlNetworkFlow) {
        self.flows.write().unwrap().push(flow);
    }

    pub fn register_policy(&self, policy: GqlPolicy) {
        self.policies.write().unwrap().push(policy);
    }

    // ---------------------------------------------------------------
    // GraphQL query resolvers
    // ---------------------------------------------------------------

    /// `query { clusters }` — returns all registered clusters.
    pub fn query_clusters(&self) -> Vec<GqlCluster> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        self.clusters.read().unwrap().clone()
    }

    /// `query { cluster(id) { nodes } }` — returns nodes for a cluster.
    pub fn query_nodes(&self, cluster_id: &str) -> Vec<GqlNode> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        self.nodes
            .read()
            .unwrap()
            .iter()
            .filter(|n| n.cluster_id == cluster_id)
            .cloned()
            .collect()
    }

    /// `query { alerts(filter) }` — returns alerts matching the filter.
    pub fn query_alerts(&self, filter: &AlertFilter) -> Vec<GqlAlert> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        let lock = self.alerts.read().unwrap();
        let limit = filter.limit.unwrap_or(100);
        lock.iter()
            .filter(|a| {
                filter
                    .cluster_id
                    .as_ref()
                    .map_or(true, |c| a.cluster_id == *c)
            })
            .filter(|a| {
                filter
                    .namespace
                    .as_ref()
                    .map_or(true, |n| a.namespace == *n)
            })
            .filter(|a| filter.severity.map_or(true, |s| a.severity == s))
            .filter(|a| filter.resolved.map_or(true, |r| a.resolved == r))
            .take(limit)
            .cloned()
            .collect()
    }

    /// `query { workloads(clusterId, namespace) }` — workload risk profiles.
    pub fn query_workloads(
        &self,
        cluster_id: Option<&str>,
        namespace: Option<&str>,
    ) -> Vec<GqlWorkload> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        self.workloads
            .read()
            .unwrap()
            .iter()
            .filter(|w| cluster_id.map_or(true, |c| w.cluster_id == c))
            .filter(|w| namespace.map_or(true, |n| w.namespace == n))
            .cloned()
            .collect()
    }

    /// `query { flows(filter) }` — network flow records.
    pub fn query_flows(&self, filter: &FlowFilter) -> Vec<GqlNetworkFlow> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        let lock = self.flows.read().unwrap();
        let limit = filter.limit.unwrap_or(200);
        lock.iter()
            .filter(|f| {
                filter
                    .cluster_id
                    .as_ref()
                    .map_or(true, |c| f.namespace.contains(c.as_str()) || true)
            })
            .filter(|f| {
                filter
                    .namespace
                    .as_ref()
                    .map_or(true, |n| f.namespace == *n)
            })
            .filter(|f| filter.src_ip.as_ref().map_or(true, |ip| f.src_ip == *ip))
            .filter(|f| filter.dst_ip.as_ref().map_or(true, |ip| f.dst_ip == *ip))
            .take(limit)
            .cloned()
            .collect()
    }

    /// `query { policies(clusterId) }` — security policies.
    pub fn query_policies(&self, cluster_id: Option<&str>) -> Vec<GqlPolicy> {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        self.policies
            .read()
            .unwrap()
            .iter()
            .filter(|p| cluster_id.map_or(true, |c| p.cluster_id == c))
            .cloned()
            .collect()
    }

    /// REST: `GET /api/v1/clusters` — OpenAPI JSON response envelope.
    pub fn rest_list_clusters(&self) -> serde_json::Value {
        self.stats.queries_total.fetch_add(1, Ordering::Relaxed);
        let clusters = self.clusters.read().unwrap().clone();
        serde_json::json!({
            "apiVersion": "kwall.io/v1",
            "kind": "ClusterList",
            "items": clusters,
            "count": clusters.len(),
        })
    }

    /// REST: `GET /api/v1/alerts` — filtered alert listing.
    pub fn rest_list_alerts(&self, filter: &AlertFilter) -> serde_json::Value {
        let alerts = self.query_alerts(filter);
        serde_json::json!({
            "apiVersion": "kwall.io/v1",
            "kind": "AlertList",
            "items": alerts,
            "count": alerts.len(),
        })
    }

    /// Generates an OpenAPI v3.0 specification for the REST surface.
    pub fn openapi_spec(&self) -> serde_json::Value {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": {
                "title": "KWALL Security API",
                "version": "1.0.0",
                "description": "Enterprise multi-cluster Kubernetes security management API"
            },
            "servers": [{ "url": "/api/v1" }],
            "paths": {
                "/clusters": {
                    "get": {
                        "operationId": "listClusters",
                        "summary": "List all federated clusters",
                        "responses": {
                            "200": { "description": "Cluster list" }
                        }
                    }
                },
                "/alerts": {
                    "get": {
                        "operationId": "listAlerts",
                        "summary": "Query active threat alerts",
                        "parameters": [
                            { "name": "cluster_id", "in": "query", "schema": { "type": "string" } },
                            { "name": "namespace", "in": "query", "schema": { "type": "string" } },
                            { "name": "severity", "in": "query", "schema": { "type": "string" } },
                            { "name": "limit", "in": "query", "schema": { "type": "integer" } }
                        ],
                        "responses": { "200": { "description": "Alert list" } }
                    }
                },
                "/flows": {
                    "get": {
                        "operationId": "listFlows",
                        "summary": "Query network flow records",
                        "responses": { "200": { "description": "Flow list" } }
                    }
                },
                "/policies": {
                    "get": {
                        "operationId": "listPolicies",
                        "summary": "List security policies",
                        "responses": { "200": { "description": "Policy list" } }
                    }
                },
                "/policies/validate": {
                    "post": {
                        "operationId": "validatePolicy",
                        "summary": "Validate a policy YAML before applying",
                        "responses": { "200": { "description": "Validation result" } }
                    }
                },
                "/compliance/{framework}": {
                    "get": {
                        "operationId": "generateComplianceReport",
                        "summary": "Generate compliance report (SOC2, PCI-DSS, CIS)",
                        "parameters": [
                            { "name": "framework", "in": "path", "required": true, "schema": { "type": "string" } }
                        ],
                        "responses": { "200": { "description": "Compliance report" } }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gateway() -> GraphQLGateway {
        let gw = GraphQLGateway::new();
        gw.register_cluster(GqlCluster {
            id: "prod-us-east".to_string(),
            name: "Production US-East".to_string(),
            provider: ClusterProvider::AwsEks,
            region: "us-east-1".to_string(),
            status: ClusterStatus::Connected,
            kubernetes_version: "1.30".to_string(),
            node_count: 12,
            total_alerts: 42,
            total_policies: 8,
        });
        gw.register_cluster(GqlCluster {
            id: "staging-eu".to_string(),
            name: "Staging EU".to_string(),
            provider: ClusterProvider::GcpGke,
            region: "europe-west1".to_string(),
            status: ClusterStatus::Connected,
            kubernetes_version: "1.29".to_string(),
            node_count: 4,
            total_alerts: 5,
            total_policies: 3,
        });
        gw.register_node(GqlNode {
            id: "n-1".to_string(),
            hostname: "ip-10-0-1-42".to_string(),
            cluster_id: "prod-us-east".to_string(),
            ebpf_ready: true,
            lsm_supported: true,
            xdp_supported: true,
            kernel_version: "6.1.0".to_string(),
            agent_version: "0.1.0".to_string(),
            workload_count: 35,
        });
        gw.register_node(GqlNode {
            id: "n-2".to_string(),
            hostname: "ip-10-0-2-17".to_string(),
            cluster_id: "prod-us-east".to_string(),
            ebpf_ready: true,
            lsm_supported: false,
            xdp_supported: true,
            kernel_version: "5.15.0".to_string(),
            agent_version: "0.1.0".to_string(),
            workload_count: 20,
        });
        gw.ingest_alert(GqlAlert {
            id: "alert-001".to_string(),
            cluster_id: "prod-us-east".to_string(),
            node_id: "n-1".to_string(),
            namespace: "payments".to_string(),
            workload: "payment-api".to_string(),
            severity: AlertSeverity::Critical,
            category: "SQLi".to_string(),
            mitre_tactic: Some("T1190".to_string()),
            mitre_technique: Some("Exploit Public-Facing Application".to_string()),
            description: "SQL injection detected in /api/v1/users".to_string(),
            timestamp_ns: 1_700_000_000_000_000_000,
            resolved: false,
        });
        gw.ingest_alert(GqlAlert {
            id: "alert-002".to_string(),
            cluster_id: "prod-us-east".to_string(),
            node_id: "n-1".to_string(),
            namespace: "monitoring".to_string(),
            workload: "prometheus".to_string(),
            severity: AlertSeverity::Warning,
            category: "PortScan".to_string(),
            mitre_tactic: None,
            mitre_technique: None,
            description: "Port scan detected from monitoring pod".to_string(),
            timestamp_ns: 1_700_000_001_000_000_000,
            resolved: true,
        });
        gw.ingest_workload(GqlWorkload {
            pod_name: "payment-api-7d9f".to_string(),
            namespace: "payments".to_string(),
            cluster_id: "prod-us-east".to_string(),
            node_id: "n-1".to_string(),
            risk_score: 87.5,
            risk_tier: "CRITICAL".to_string(),
            container_count: 2,
            alert_count: 1,
        });
        gw.register_policy(GqlPolicy {
            id: "pol-001".to_string(),
            name: "deny-public-egress".to_string(),
            namespace: "payments".to_string(),
            cluster_id: "prod-us-east".to_string(),
            kind: PolicyKind::KwallNetworkPolicy,
            action: PolicyAction::Deny,
            rule_count: 3,
            applied: true,
        });
        gw
    }

    #[test]
    fn test_query_clusters() {
        let gw = make_gateway();
        let clusters = gw.query_clusters();
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].id, "prod-us-east");
        assert_eq!(clusters[1].provider, ClusterProvider::GcpGke);
    }

    #[test]
    fn test_query_nodes_by_cluster() {
        let gw = make_gateway();
        let nodes = gw.query_nodes("prod-us-east");
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.ebpf_ready));
        let empty = gw.query_nodes("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_query_alerts_unfiltered() {
        let gw = make_gateway();
        let alerts = gw.query_alerts(&AlertFilter::default());
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn test_query_alerts_filter_by_severity() {
        let gw = make_gateway();
        let critical = gw.query_alerts(&AlertFilter {
            severity: Some(AlertSeverity::Critical),
            ..Default::default()
        });
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].id, "alert-001");
    }

    #[test]
    fn test_query_alerts_filter_by_namespace() {
        let gw = make_gateway();
        let monitoring = gw.query_alerts(&AlertFilter {
            namespace: Some("monitoring".to_string()),
            ..Default::default()
        });
        assert_eq!(monitoring.len(), 1);
        assert!(monitoring[0].resolved);
    }

    #[test]
    fn test_query_alerts_filter_resolved() {
        let gw = make_gateway();
        let unresolved = gw.query_alerts(&AlertFilter {
            resolved: Some(false),
            ..Default::default()
        });
        assert_eq!(unresolved.len(), 1);
    }

    #[test]
    fn test_query_workloads() {
        let gw = make_gateway();
        let all = gw.query_workloads(None, None);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].risk_tier, "CRITICAL");

        let by_ns = gw.query_workloads(Some("prod-us-east"), Some("payments"));
        assert_eq!(by_ns.len(), 1);
    }

    #[test]
    fn test_query_policies() {
        let gw = make_gateway();
        let pols = gw.query_policies(Some("prod-us-east"));
        assert_eq!(pols.len(), 1);
        assert_eq!(pols[0].kind, PolicyKind::KwallNetworkPolicy);
        assert!(pols[0].applied);
    }

    #[test]
    fn test_rest_list_clusters_json_envelope() {
        let gw = make_gateway();
        let json = gw.rest_list_clusters();
        assert_eq!(json["apiVersion"], "kwall.io/v1");
        assert_eq!(json["kind"], "ClusterList");
        assert_eq!(json["count"], 2);
    }

    #[test]
    fn test_rest_list_alerts_filtered() {
        let gw = make_gateway();
        let json = gw.rest_list_alerts(&AlertFilter {
            severity: Some(AlertSeverity::Critical),
            ..Default::default()
        });
        assert_eq!(json["count"], 1);
    }

    #[test]
    fn test_openapi_spec_generation() {
        let gw = make_gateway();
        let spec = gw.openapi_spec();
        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["info"]["title"], "KWALL Security API");
        let paths = spec["paths"].as_object().unwrap();
        assert!(paths.contains_key("/clusters"));
        assert!(paths.contains_key("/alerts"));
        assert!(paths.contains_key("/flows"));
        assert!(paths.contains_key("/policies"));
        assert!(paths.contains_key("/policies/validate"));
        assert!(paths.contains_key("/compliance/{framework}"));
    }

    #[test]
    fn test_gateway_stats_tracked() {
        let gw = make_gateway();
        gw.query_clusters();
        gw.query_nodes("prod-us-east");
        gw.query_alerts(&AlertFilter::default());
        let (queries, _, _) = gw.stats().snapshot();
        assert_eq!(queries, 3);
    }
}
