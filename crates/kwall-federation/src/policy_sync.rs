//! # Global Network Policy Federation & Cross-Cluster Identity Sync
//!
//! Provides global security policy synchronization across multi-region Kubernetes clusters.
//! Automatically translates abstract federated rules into cluster-local `KwallNetworkPolicy`
//! and `KwallRuntimePolicy` specifications, accounting for cloud provider CIDR blocks,
//! and maintains SPIFFE federated trust domain bundles for mutual identity validation.

use crate::control_plane::{CloudProvider, ClusterDescriptor};
use kwall_identity::SpiffeId;
use kwall_policy::crd::{KwallNetworkPolicySpec, NetworkPolicyAction, NetworkRule};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Errors occurring during federated policy translation and identity sync.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicySyncError {
    #[error("Policy '{0}' already exists in federation repository")]
    PolicyAlreadyExists(String),

    #[error("Policy '{0}' not found")]
    PolicyNotFound(String),

    #[error("Failed to translate rule {0}: invalid CIDR or format '{1}'")]
    TranslationFailed(u32, String),

    #[error("Trust domain '{0}' is not authorized in federation")]
    UntrustedDomain(String),

    #[error("SPIFFE ID '{0}' is invalid: {1}")]
    InvalidSpiffeId(String, String),

    #[error("Cluster selector does not match target cluster '{0}'")]
    ClusterSelectorMismatch(String),
}

/// Selector specifying which member clusters should enforce a federated policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterSelector {
    /// Applies to all federated clusters.
    All,
    /// Applies to a specific list of cluster IDs.
    Specific(Vec<String>),
    /// Matches clusters by cloud provider.
    ByProvider(CloudProvider),
    /// Matches clusters by key-value label tags.
    ByLabel(HashMap<String, String>),
}

impl ClusterSelector {
    /// Evaluates if a given cluster matches the selector criteria.
    pub fn matches(&self, cluster: &ClusterDescriptor) -> bool {
        match self {
            Self::All => true,
            Self::Specific(ids) => ids.contains(&cluster.cluster_id),
            Self::ByProvider(provider) => cluster.provider == *provider,
            Self::ByLabel(required_labels) => required_labels
                .iter()
                .all(|(k, v)| cluster.labels.get(k) == Some(v)),
        }
    }
}

/// Abstract cross-cluster network rule declared at global level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossClusterRule {
    pub rule_id: u32,
    pub description: String,
    pub source_trust_domains: Vec<String>,
    pub source_namespaces: Vec<String>,
    pub destination_clusters: Vec<String>,
    pub destination_cidrs: Vec<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub action: NetworkPolicyAction,
    pub allowed_spiffe_identities: Vec<String>,
}

/// Top-level federated security policy orchestrating zero-trust multi-cluster security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedSecurityPolicy {
    pub policy_id: String,
    pub name: String,
    pub version: u64,
    pub selector: ClusterSelector,
    pub rules: Vec<CrossClusterRule>,
    pub created_at_ns: u64,
}

/// Trust bundle representing public CA keys and authorized remote domains for a SPIFFE trust domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDomainBundle {
    pub trust_domain: String,
    pub root_ca_pem: String,
    pub valid_until_timestamp_ns: u64,
    pub authorized_federations: Vec<String>,
}

/// Cross-Cluster Identity Synchronizer managing SPIFFE trust domain federation.
pub struct CrossClusterIdentitySync {
    trust_bundles: Arc<RwLock<HashMap<String, TrustDomainBundle>>>,
}

impl Default for CrossClusterIdentitySync {
    fn default() -> Self {
        Self {
            trust_bundles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl CrossClusterIdentitySync {
    /// Registers or updates a SPIFFE trust domain bundle.
    pub fn register_trust_bundle(&self, bundle: TrustDomainBundle) {
        tracing::info!(
            trust_domain = %bundle.trust_domain,
            authorized = ?bundle.authorized_federations,
            "Synchronized SPIFFE trust domain bundle"
        );
        let mut bundles = self.trust_bundles.write().unwrap();
        bundles.insert(bundle.trust_domain.clone(), bundle);
    }

    /// Validates whether a caller's SPIFFE ID is authorized to communicate with a target trust domain.
    pub fn validate_cross_cluster_identity(
        &self,
        caller_spiffe_str: &str,
        target_trust_domain: &str,
        current_time_ns: u64,
    ) -> Result<SpiffeId, PolicySyncError> {
        let spiffe = SpiffeId::parse(caller_spiffe_str).map_err(|e| {
            PolicySyncError::InvalidSpiffeId(caller_spiffe_str.to_string(), e.to_string())
        })?;

        let caller_domain = &spiffe.trust_domain;

        // Same trust domain is inherently trusted
        if caller_domain == target_trust_domain {
            return Ok(spiffe);
        }

        // Cross-domain verification requires valid trust bundle federation
        let bundles = self.trust_bundles.read().unwrap();
        let target_bundle = bundles
            .get(target_trust_domain)
            .ok_or_else(|| PolicySyncError::UntrustedDomain(target_trust_domain.to_string()))?;

        if current_time_ns > target_bundle.valid_until_timestamp_ns {
            return Err(PolicySyncError::UntrustedDomain(format!(
                "Trust bundle for '{}' expired",
                target_trust_domain
            )));
        }

        if !target_bundle
            .authorized_federations
            .contains(&caller_domain.to_string())
        {
            return Err(PolicySyncError::UntrustedDomain(format!(
                "Trust domain '{}' not authorized to federate with '{}'",
                caller_domain, target_trust_domain
            )));
        }

        Ok(spiffe)
    }

    /// Returns all registered trust domain names.
    pub fn list_trust_domains(&self) -> Vec<String> {
        self.trust_bundles.read().unwrap().keys().cloned().collect()
    }
}

/// Translation engine mapping abstract federated policies to cluster-local `KwallNetworkPolicySpec`.
pub struct PolicyTranslationEngine {
    provider_default_cidrs: HashMap<CloudProvider, Vec<String>>,
}

impl Default for PolicyTranslationEngine {
    fn default() -> Self {
        let mut provider_default_cidrs = HashMap::new();
        // Standard cloud provider Pod/Node CIDR conventions
        provider_default_cidrs.insert(
            CloudProvider::AwsEks,
            vec!["10.100.0.0/16".to_string(), "10.101.0.0/16".to_string()],
        );
        provider_default_cidrs.insert(
            CloudProvider::GcpGke,
            vec!["10.4.0.0/14".to_string(), "10.8.0.0/14".to_string()],
        );
        provider_default_cidrs.insert(
            CloudProvider::AzureAks,
            vec!["10.244.0.0/16".to_string(), "10.245.0.0/16".to_string()],
        );
        provider_default_cidrs.insert(
            CloudProvider::KindCluster,
            vec!["10.244.0.0/16".to_string(), "172.18.0.0/16".to_string()],
        );
        provider_default_cidrs.insert(
            CloudProvider::BareMetal,
            vec!["192.168.0.0/16".to_string()],
        );

        Self {
            provider_default_cidrs,
        }
    }
}

impl PolicyTranslationEngine {
    /// Translates a global `FederatedSecurityPolicy` into local `KwallNetworkPolicySpec`
    /// tailored to the destination cluster's context and cloud network topology.
    pub fn translate_policy_for_cluster(
        &self,
        policy: &FederatedSecurityPolicy,
        cluster: &ClusterDescriptor,
    ) -> Result<KwallNetworkPolicySpec, PolicySyncError> {
        if !policy.selector.matches(cluster) {
            return Err(PolicySyncError::ClusterSelectorMismatch(
                cluster.cluster_id.clone(),
            ));
        }

        let mut translated_egress_rules = Vec::new();

        for rule in &policy.rules {
            // If destination cluster list is defined, ensure this cluster or its peers match
            let matches_destination = rule.destination_clusters.is_empty()
                || rule.destination_clusters.contains(&cluster.cluster_id)
                || rule.destination_clusters.contains(&"*".to_string());

            if !matches_destination {
                continue;
            }

            // Determine target CIDRs: use explicit CIDRs if given, otherwise fall back to provider CIDRs
            let cidrs = if !rule.destination_cidrs.is_empty() {
                rule.destination_cidrs.clone()
            } else if let Some(defaults) = self.provider_default_cidrs.get(&cluster.provider) {
                defaults.clone()
            } else {
                vec!["0.0.0.0/0".to_string()]
            };

            for cidr in cidrs {
                translated_egress_rules.push(NetworkRule {
                    cidr,
                    port: rule.port,
                    protocol: rule.protocol.clone(),
                    action: rule.action,
                });
            }
        }

        let mut pod_selector = HashMap::new();
        pod_selector.insert("kwall.io/federated".to_string(), "true".to_string());
        pod_selector.insert("kwall.io/policy-id".to_string(), policy.policy_id.clone());

        Ok(KwallNetworkPolicySpec {
            pod_selector,
            ingress: Some(Vec::new()),
            egress: Some(translated_egress_rules),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cluster(id: &str, provider: CloudProvider) -> ClusterDescriptor {
        let mut labels = HashMap::new();
        labels.insert("environment".to_string(), "production".to_string());
        labels.insert("region".to_string(), "us-east-1".to_string());

        ClusterDescriptor {
            cluster_id: id.to_string(),
            name: id.to_string(),
            provider,
            region: "us-east-1".to_string(),
            api_endpoint: "https://k8s.example.com".to_string(),
            trust_domain: format!("{}.kwall.internal", id),
            node_count: 3,
            agent_count: 3,
            status: crate::control_plane::ClusterStatus::Connected,
            last_heartbeat_timestamp_ns: 1_000_000,
            kwall_version: "0.1.0".to_string(),
            labels,
        }
    }

    #[test]
    fn test_cluster_selector_matching() {
        let eks_cluster = sample_cluster("c-eks-1", CloudProvider::AwsEks);
        let gke_cluster = sample_cluster("c-gke-1", CloudProvider::GcpGke);

        // Selector: All
        assert!(ClusterSelector::All.matches(&eks_cluster));
        assert!(ClusterSelector::All.matches(&gke_cluster));

        // Selector: ByProvider
        let eks_selector = ClusterSelector::ByProvider(CloudProvider::AwsEks);
        assert!(eks_selector.matches(&eks_cluster));
        assert!(!eks_selector.matches(&gke_cluster));

        // Selector: Specific
        let specific_selector = ClusterSelector::Specific(vec!["c-eks-1".to_string()]);
        assert!(specific_selector.matches(&eks_cluster));
        assert!(!specific_selector.matches(&gke_cluster));

        // Selector: ByLabel
        let mut matching_label = HashMap::new();
        matching_label.insert("environment".to_string(), "production".to_string());
        assert!(ClusterSelector::ByLabel(matching_label).matches(&eks_cluster));
    }

    #[test]
    fn test_federated_policy_translation() {
        let engine = PolicyTranslationEngine::default();
        let eks_cluster = sample_cluster("c-eks-1", CloudProvider::AwsEks);

        let global_policy = FederatedSecurityPolicy {
            policy_id: "fed-pol-001".to_string(),
            name: "cross-cluster-database-access".to_string(),
            version: 1,
            selector: ClusterSelector::ByProvider(CloudProvider::AwsEks),
            created_at_ns: 1_000_000,
            rules: vec![CrossClusterRule {
                rule_id: 101,
                description: "Allow egress to payment DB in AWS".to_string(),
                source_trust_domains: vec!["c-eks-1.kwall.internal".to_string()],
                source_namespaces: vec!["payments".to_string()],
                destination_clusters: vec!["c-eks-1".to_string()],
                destination_cidrs: vec!["10.100.20.0/24".to_string()],
                port: Some(5432),
                protocol: Some("tcp".to_string()),
                action: NetworkPolicyAction::Allow,
                allowed_spiffe_identities: vec!["spiffe://c-eks-1.kwall.internal/ns/payments/sa/payment-service".to_string()],
            }],
        };

        let translated = engine
            .translate_policy_for_cluster(&global_policy, &eks_cluster)
            .unwrap();

        let egress = translated.egress.as_ref().unwrap();
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].cidr, "10.100.20.0/24");
        assert_eq!(egress[0].port, Some(5432));
        assert_eq!(egress[0].action, NetworkPolicyAction::Allow);
        assert_eq!(
            translated.pod_selector.get("kwall.io/policy-id"),
            Some(&"fed-pol-001".to_string())
        );
    }

    #[test]
    fn test_cross_cluster_spiffe_validation() {
        let sync = CrossClusterIdentitySync::default();

        let bundle = TrustDomainBundle {
            trust_domain: "gke.prod.kwall".to_string(),
            root_ca_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----".to_string(),
            valid_until_timestamp_ns: 100_000_000_000,
            authorized_federations: vec!["eks.prod.kwall".to_string()],
        };

        sync.register_trust_bundle(bundle);

        // Same trust domain -> passes
        let same_res = sync.validate_cross_cluster_identity(
            "spiffe://gke.prod.kwall/ns/backend/sa/app",
            "gke.prod.kwall",
            50_000_000_000,
        );
        assert!(same_res.is_ok());

        // Authorized cross domain -> passes
        let cross_res = sync.validate_cross_cluster_identity(
            "spiffe://eks.prod.kwall/ns/frontend/sa/web",
            "gke.prod.kwall",
            50_000_000_000,
        );
        assert!(cross_res.is_ok());
        let spiffe = cross_res.unwrap();
        assert_eq!(spiffe.namespace, "frontend");
        assert_eq!(spiffe.service_account, "web");

        // Unauthorized domain -> rejected
        let unauthorized_res = sync.validate_cross_cluster_identity(
            "spiffe://rogue.untrusted.domain/ns/frontend/sa/web",
            "gke.prod.kwall",
            50_000_000_000,
        );
        assert!(matches!(
            unauthorized_res,
            Err(PolicySyncError::UntrustedDomain(_))
        ));
    }
}
