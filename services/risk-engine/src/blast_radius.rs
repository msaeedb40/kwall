//! # Graph-Based Blast Radius Analyzer
//!
//! Models directed cluster dependency and communication graphs to compute the potential
//! lateral movement blast radius from any compromised workload. Identifies exposed crown-jewel
//! assets (e.g. databases, Kubernetes API server, cloud metadata service `169.254.169.254`,
//! and secrets) reachable within N hops.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

/// Classification of cluster asset criticality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssetCriticality {
    Standard,
    High,
    CrownJewel,
}

impl std::fmt::Display for AssetCriticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "STANDARD"),
            Self::High => write!(f, "HIGH"),
            Self::CrownJewel => write!(f, "CROWN_JEWEL"),
        }
    }
}

/// Asset node in the cluster communication graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetNode {
    pub asset_id: String,
    pub name: String,
    pub namespace: String,
    pub criticality: AssetCriticality,
    pub is_cloud_metadata_service: bool,
    pub is_k8s_api_server: bool,
    pub is_database: bool,
}

/// Lateral movement path step in the blast radius reachability tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementHop {
    pub from_asset: String,
    pub to_asset: String,
    pub protocol: String,
    pub port: u16,
    pub hop_distance: u32,
}

/// Comprehensive Blast Radius assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusReport {
    pub origin_workload_id: String,
    pub max_hops: u32,
    pub total_reachable_assets: usize,
    pub reachable_crown_jewels: Vec<String>,
    pub cloud_metadata_reachable: bool,
    pub k8s_api_server_reachable: bool,
    pub blast_severity: BlastSeverity,
    pub movement_paths: Vec<LateralMovementHop>,
    pub analyzed_at_ns: u64,
}

/// Calculated severity of the lateral movement blast radius.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlastSeverity {
    Contained,
    Moderate,
    Severe,
    Catastrophic,
}

impl std::fmt::Display for BlastSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Contained => write!(f, "CONTAINED"),
            Self::Moderate => write!(f, "MODERATE"),
            Self::Severe => write!(f, "SEVERE"),
            Self::Catastrophic => write!(f, "CATASTROPHIC"),
        }
    }
}

/// Graph-Based Blast Radius Analyzer.
pub struct BlastRadiusAnalyzer {
    nodes: Arc<RwLock<HashMap<String, AssetNode>>>,
    edges: Arc<RwLock<HashMap<String, Vec<(String, String, u16)>>>>, // from -> [(to, protocol, port)]
}

impl Default for BlastRadiusAnalyzer {
    fn default() -> Self {
        let analyzer = Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            edges: Arc::new(RwLock::new(HashMap::new())),
        };

        // Pre-register well-known cluster infrastructure assets
        analyzer.register_asset(AssetNode {
            asset_id: "infra:cloud-metadata".to_string(),
            name: "Cloud Metadata Service (169.254.169.254)".to_string(),
            namespace: "kube-system".to_string(),
            criticality: AssetCriticality::CrownJewel,
            is_cloud_metadata_service: true,
            is_k8s_api_server: false,
            is_database: false,
        });

        analyzer.register_asset(AssetNode {
            asset_id: "infra:k8s-apiserver".to_string(),
            name: "Kubernetes API Server".to_string(),
            namespace: "default".to_string(),
            criticality: AssetCriticality::CrownJewel,
            is_cloud_metadata_service: false,
            is_k8s_api_server: true,
            is_database: false,
        });

        analyzer
    }
}

impl BlastRadiusAnalyzer {
    /// Registers an asset node in the cluster topology graph.
    pub fn register_asset(&self, node: AssetNode) {
        let mut nodes = self.nodes.write().unwrap();
        nodes.insert(node.asset_id.clone(), node);
    }

    /// Records an allowable network/service dependency communication edge.
    pub fn add_dependency_edge(&self, from_id: &str, to_id: &str, protocol: &str, port: u16) {
        let mut edges = self.edges.write().unwrap();
        edges
            .entry(from_id.to_string())
            .or_default()
            .push((to_id.to_string(), protocol.to_string(), port));
    }

    /// Computes the lateral movement blast radius from a compromised origin workload up to `max_hops`.
    pub fn compute_blast_radius(
        &self,
        origin_id: &str,
        max_hops: u32,
        timestamp_ns: u64,
    ) -> BlastRadiusReport {
        let nodes = self.nodes.read().unwrap();
        let edges = self.edges.read().unwrap();

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut movement_paths = Vec::new();
        let mut reachable_crown_jewels = Vec::new();
        let mut cloud_metadata_reachable = false;
        let mut k8s_api_server_reachable = false;

        visited.insert(origin_id.to_string());
        queue.push_back((origin_id.to_string(), 0));

        while let Some((current_id, current_hop)) = queue.pop_front() {
            if current_hop >= max_hops {
                continue;
            }

            if let Some(neighbors) = edges.get(&current_id) {
                for (target_id, proto, port) in neighbors {
                    movement_paths.push(LateralMovementHop {
                        from_asset: current_id.clone(),
                        to_asset: target_id.clone(),
                        protocol: proto.clone(),
                        port: *port,
                        hop_distance: current_hop + 1,
                    });

                    if visited.insert(target_id.clone()) {
                        if let Some(target_node) = nodes.get(target_id) {
                            if target_node.criticality == AssetCriticality::CrownJewel {
                                reachable_crown_jewels.push(target_node.name.clone());
                            }
                            if target_node.is_cloud_metadata_service {
                                cloud_metadata_reachable = true;
                            }
                            if target_node.is_k8s_api_server {
                                k8s_api_server_reachable = true;
                            }
                        }

                        queue.push_back((target_id.clone(), current_hop + 1));
                    }
                }
            }
        }

        let total_reachable = visited.len().saturating_sub(1); // exclude origin itself

        let blast_severity = if cloud_metadata_reachable || k8s_api_server_reachable || reachable_crown_jewels.len() >= 2 {
            BlastSeverity::Catastrophic
        } else if !reachable_crown_jewels.is_empty() || total_reachable >= 5 {
            BlastSeverity::Severe
        } else if total_reachable > 1 {
            BlastSeverity::Moderate
        } else {
            BlastSeverity::Contained
        };

        BlastRadiusReport {
            origin_workload_id: origin_id.to_string(),
            max_hops,
            total_reachable_assets: total_reachable,
            reachable_crown_jewels,
            cloud_metadata_reachable,
            k8s_api_server_reachable,
            blast_severity,
            movement_paths,
            analyzed_at_ns: timestamp_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blast_radius_reaches_database_and_metadata() {
        let analyzer = BlastRadiusAnalyzer::default();

        // Register custom app assets
        analyzer.register_asset(AssetNode {
            asset_id: "app:frontend".to_string(),
            name: "Frontend Web Service".to_string(),
            namespace: "prod".to_string(),
            criticality: AssetCriticality::Standard,
            is_cloud_metadata_service: false,
            is_k8s_api_server: false,
            is_database: false,
        });

        analyzer.register_asset(AssetNode {
            asset_id: "app:backend".to_string(),
            name: "Backend Order API".to_string(),
            namespace: "prod".to_string(),
            criticality: AssetCriticality::High,
            is_cloud_metadata_service: false,
            is_k8s_api_server: false,
            is_database: false,
        });

        analyzer.register_asset(AssetNode {
            asset_id: "db:postgres".to_string(),
            name: "Production Customer Postgres DB".to_string(),
            namespace: "data".to_string(),
            criticality: AssetCriticality::CrownJewel,
            is_cloud_metadata_service: false,
            is_k8s_api_server: false,
            is_database: true,
        });

        // Dependencies: Frontend -> Backend -> Postgres DB
        analyzer.add_dependency_edge("app:frontend", "app:backend", "HTTP", 8080);
        analyzer.add_dependency_edge("app:backend", "db:postgres", "TCP", 5432);
        // Backend also has egress to cloud metadata
        analyzer.add_dependency_edge("app:backend", "infra:cloud-metadata", "HTTP", 80);

        // Analyze blast radius from compromised frontend (max 2 hops)
        let report = analyzer.compute_blast_radius("app:frontend", 2, 1_000_000);

        assert_eq!(report.total_reachable_assets, 3);
        assert!(report.cloud_metadata_reachable);
        assert!(report
            .reachable_crown_jewels
            .iter()
            .any(|n| n.contains("Postgres")));
        assert_eq!(report.blast_severity, BlastSeverity::Catastrophic);
        assert_eq!(report.movement_paths.len(), 3);
    }

    #[test]
    fn test_isolated_workload_contained_blast_radius() {
        let analyzer = BlastRadiusAnalyzer::default();

        analyzer.register_asset(AssetNode {
            asset_id: "app:isolated".to_string(),
            name: "Batch Compute Job".to_string(),
            namespace: "jobs".to_string(),
            criticality: AssetCriticality::Standard,
            is_cloud_metadata_service: false,
            is_k8s_api_server: false,
            is_database: false,
        });

        let report = analyzer.compute_blast_radius("app:isolated", 3, 1_000_000);
        assert_eq!(report.total_reachable_assets, 0);
        assert_eq!(report.blast_severity, BlastSeverity::Contained);
        assert!(!report.cloud_metadata_reachable);
        assert!(!report.k8s_api_server_reachable);
    }
}
