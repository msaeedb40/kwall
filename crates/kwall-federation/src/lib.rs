//! # kwall-federation: Multi-Cluster Federation & Enterprise Identity
//!
//! Provides enterprise-grade multi-cluster security federation, cross-cloud policy translation,
//! SPIFFE identity trust bundle synchronization, CNI & Service Mesh interoperability, and
//! Open Policy Agent (OPA) / Rego admission control and compliance auditing for KWALL.
//!
//! ## Subsystems
//!
//! 1. **Control Plane (`control_plane`)**:
//!    Multi-cluster registry, remote health monitoring, heartbeat tracking, and aggregated
//!    security telemetry and service topology.
//! 2. **Policy Sync (`policy_sync`)**:
//!    Declarative federated security policies automatically translated into cluster-local
//!    `KwallNetworkPolicy` and `KwallRuntimePolicy` specs, with cross-cluster SPIFFE trust federation.
//! 3. **Mesh Interoperability (`mesh_interop`)**:
//!    Zero-conflict coexistence with Cilium 1.20+, Calico, Flannel, AWS VPC CNI, and Istio/Linkerd
//!    service meshes via TC filter priority chains and isolated BPF map namespacing.
//! 4. **OPA / Rego Engine (`opa_engine`)**:
//!    Enterprise admission review and continuous compliance audits enforcing CIS Kubernetes
//!    Benchmarks, PCI-DSS v4, and SOC2 zero-trust standards.

pub mod control_plane;
pub mod mesh_interop;
pub mod opa_engine;
pub mod policy_sync;

pub use control_plane::{
    AggregatedTelemetryMetrics, CloudProvider, ClusterDescriptor, ClusterStatus, ControlPlaneError,
    CrossClusterSecurityEvent, GlobalControlPlane, GlobalTelemetryAggregator, ServiceGraphEdge,
    ServiceGraphNode,
};
pub use mesh_interop::{
    CniProvider, EnvironmentProbe, MeshInteropManager, MeshInteropReport, MeshProvider,
};
pub use opa_engine::{
    AdmissionReviewDecision, AdmissionReviewPodSpec, ComplianceStandard, ContainerSecurityContext,
    OpaPolicyEngine, OpaRule, OpaViolation, ViolationSeverity,
};
pub use policy_sync::{
    ClusterSelector, CrossClusterIdentitySync, CrossClusterRule, FederatedSecurityPolicy,
    PolicySyncError, PolicyTranslationEngine, TrustDomainBundle,
};

use std::sync::Arc;

/// Unified Federation Manager coordinating multi-cluster policies, identity sync, and compliance.
pub struct FederationManager {
    pub control_plane: Arc<GlobalControlPlane>,
    pub telemetry_aggregator: Arc<GlobalTelemetryAggregator>,
    pub identity_sync: Arc<CrossClusterIdentitySync>,
    pub translation_engine: Arc<PolicyTranslationEngine>,
    pub mesh_interop: Arc<MeshInteropManager>,
    pub opa_engine: Arc<OpaPolicyEngine>,
}

impl Default for FederationManager {
    fn default() -> Self {
        Self {
            control_plane: Arc::new(GlobalControlPlane::default()),
            telemetry_aggregator: Arc::new(GlobalTelemetryAggregator::default()),
            identity_sync: Arc::new(CrossClusterIdentitySync::default()),
            translation_engine: Arc::new(PolicyTranslationEngine::default()),
            mesh_interop: Arc::new(MeshInteropManager::default()),
            opa_engine: Arc::new(OpaPolicyEngine::default()),
        }
    }
}

impl FederationManager {
    /// Creates a customized federation manager.
    pub fn new(
        control_plane: GlobalControlPlane,
        telemetry_aggregator: GlobalTelemetryAggregator,
        identity_sync: CrossClusterIdentitySync,
        translation_engine: PolicyTranslationEngine,
        mesh_interop: MeshInteropManager,
        opa_engine: OpaPolicyEngine,
    ) -> Self {
        Self {
            control_plane: Arc::new(control_plane),
            telemetry_aggregator: Arc::new(telemetry_aggregator),
            identity_sync: Arc::new(identity_sync),
            translation_engine: Arc::new(translation_engine),
            mesh_interop: Arc::new(mesh_interop),
            opa_engine: Arc::new(opa_engine),
        }
    }

    /// Deploys and translates a federated policy to a target cluster, validating cluster health first.
    pub fn deploy_policy_to_cluster(
        &self,
        policy: &FederatedSecurityPolicy,
        cluster_id: &str,
    ) -> Result<kwall_policy::crd::KwallNetworkPolicySpec, String> {
        let cluster = self
            .control_plane
            .get_cluster(cluster_id)
            .ok_or_else(|| format!("Target cluster '{}' not registered", cluster_id))?;

        if cluster.status == ClusterStatus::Disconnected {
            return Err(format!("Cluster '{}' is currently disconnected", cluster_id));
        }

        self.translation_engine
            .translate_policy_for_cluster(policy, &cluster)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_manager_end_to_end() {
        let manager = FederationManager::default();

        // 1. Register cluster
        let cluster = ClusterDescriptor {
            cluster_id: "c-prod-aws-01".to_string(),
            name: "AWS EKS Production".to_string(),
            provider: CloudProvider::AwsEks,
            region: "us-east-1".to_string(),
            api_endpoint: "https://eks.us-east-1.amazonaws.com".to_string(),
            trust_domain: "aws-prod.kwall.internal".to_string(),
            node_count: 10,
            agent_count: 10,
            status: ClusterStatus::Connected,
            last_heartbeat_timestamp_ns: 1_000_000,
            kwall_version: "0.1.0".to_string(),
            labels: [("tier".to_string(), "prod".to_string())]
                .into_iter()
                .collect(),
        };

        manager.control_plane.register_cluster(cluster).unwrap();

        // 2. Define and deploy global policy
        let policy = FederatedSecurityPolicy {
            policy_id: "fed-global-01".to_string(),
            name: "global-zero-trust".to_string(),
            version: 1,
            selector: ClusterSelector::All,
            rules: vec![CrossClusterRule {
                rule_id: 1,
                description: "Allow egress to internal API".to_string(),
                source_trust_domains: vec!["aws-prod.kwall.internal".to_string()],
                source_namespaces: vec!["default".to_string()],
                destination_clusters: vec!["c-prod-aws-01".to_string()],
                destination_cidrs: vec!["10.100.0.0/16".to_string()],
                port: Some(443),
                protocol: Some("tcp".to_string()),
                action: kwall_policy::crd::NetworkPolicyAction::Allow,
                allowed_spiffe_identities: Vec::new(),
            }],
            created_at_ns: 1_000_000,
        };

        let translated = manager
            .deploy_policy_to_cluster(&policy, "c-prod-aws-01")
            .unwrap();

        let egress = translated.egress.as_ref().unwrap();
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].cidr, "10.100.0.0/16");
        assert_eq!(egress[0].port, Some(443));

        // 3. Evaluate admission compliance with OPA engine
        let pod = AdmissionReviewPodSpec {
            name: "api-gateway".to_string(),
            namespace: "prod".to_string(),
            host_network: false,
            host_pid: false,
            host_ipc: false,
            containers: vec![ContainerSecurityContext {
                name: "gateway".to_string(),
                image: "kwall/gateway:latest".to_string(),
                run_as_user: Some(1001),
                run_as_non_root: Some(true),
                allow_privilege_escalation: Some(false),
                privileged: Some(false),
                read_only_root_filesystem: Some(true),
                capabilities_add: Vec::new(),
                capabilities_drop: vec!["ALL".to_string()],
            }],
            labels: [("kwall.io/policy-domain".to_string(), "api".to_string())]
                .into_iter()
                .collect(),
        };

        let decision = manager.opa_engine.evaluate_pod(&pod);
        assert!(decision.allowed);
        assert_eq!(decision.status_code, 200);

        // 4. Test disconnected cluster rejection
        manager
            .control_plane
            .evaluate_cluster_health(1_000_000 + 200_000_000_000);
        let err = manager.deploy_policy_to_cluster(&policy, "c-prod-aws-01");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("disconnected"));
    }
}
