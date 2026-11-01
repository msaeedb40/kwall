//! # kwall-risk: Dynamic Risk Assessment & Blast Radius Analysis Engine
//!
//! Provides continuous, multi-dimensional workload risk quantification, lateral movement
//! blast radius analysis across service dependency graphs, and policy-driven automated
//! security containment (network quarantine, cgroup freeze).
//!
//! ## Subsystems
//!
//! - **Workload Risk Scorer (`scorer`)**: Computes real-time 0–100 risk scores combining
//!   runtime anomalies, SBOM CVEs, network attack surfaces, and container privileges.
//! - **Blast Radius Analyzer (`blast_radius`)**: Computes reachable crown-jewel assets
//!   (databases, K8s API server, cloud metadata `169.254.169.254`) within N hops.
//! - **Containment Trigger Manager (`containment`)**: Automated response trigger enforcing
//!   network quarantine or cgroup freeze when risk thresholds are breached.

pub mod blast_radius;
pub mod containment;
pub mod cve;
pub mod scorer;

pub use blast_radius::{
    AssetCriticality, AssetNode, BlastRadiusAnalyzer, BlastRadiusReport, BlastSeverity,
    LateralMovementHop,
};
pub use containment::{
    ContainmentAction, ContainmentDecision, ContainmentPolicy, ContainmentTriggerManager,
};
pub use cve::{
    aggregate_cve_findings, summary_to_scorer_inputs, CveFinding, CveRiskSummary, CvssSeverity,
};
pub use scorer::{
    RiskTier, RiskVectors, WorkloadRiskInputs, WorkloadRiskProfile, WorkloadRiskScorer,
};

use std::sync::Arc;

/// Unified Risk Engine coordinating scoring, blast radius analysis, and containment.
pub struct RiskEngine {
    pub scorer: Arc<WorkloadRiskScorer>,
    pub blast_analyzer: Arc<BlastRadiusAnalyzer>,
    pub containment_manager: Arc<ContainmentTriggerManager>,
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self {
            scorer: Arc::new(WorkloadRiskScorer::default()),
            blast_analyzer: Arc::new(BlastRadiusAnalyzer::default()),
            containment_manager: Arc::new(ContainmentTriggerManager::default()),
        }
    }
}

impl RiskEngine {
    /// Constructs a Risk Engine with customized sub-managers.
    pub fn new(
        scorer: WorkloadRiskScorer,
        blast_analyzer: BlastRadiusAnalyzer,
        containment_manager: ContainmentTriggerManager,
    ) -> Self {
        Self {
            scorer: Arc::new(scorer),
            blast_analyzer: Arc::new(blast_analyzer),
            containment_manager: Arc::new(containment_manager),
        }
    }

    /// Evaluates a workload comprehensively: scores risk, calculates blast radius, and applies containment if required.
    pub fn assess_and_contain(
        &self,
        workload_id: &str,
        pod_name: &str,
        namespace: &str,
        inputs: &WorkloadRiskInputs,
        max_hops: u32,
        timestamp_ns: u64,
    ) -> (WorkloadRiskProfile, BlastRadiusReport, ContainmentDecision) {
        // 1. Compute multi-dimensional risk score
        let profile = self
            .scorer
            .evaluate_workload(workload_id, pod_name, namespace, inputs, timestamp_ns);

        // 2. Compute lateral movement blast radius
        let blast = self
            .blast_analyzer
            .compute_blast_radius(workload_id, max_hops, timestamp_ns);

        // 3. Evaluate automated containment
        let decision = self
            .containment_manager
            .evaluate_containment(&profile, &blast, timestamp_ns);

        (profile, blast, decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_engine_end_to_end_assessment_and_containment() {
        let engine = RiskEngine::default();

        // 1. Setup cluster assets and communication paths
        engine.blast_analyzer.register_asset(AssetNode {
            asset_id: "w-payment-ingress".to_string(),
            name: "Payment Ingress".to_string(),
            namespace: "payments".to_string(),
            criticality: AssetCriticality::Standard,
            is_cloud_metadata_service: false,
            is_k8s_api_server: false,
            is_database: false,
        });

        engine.blast_analyzer.register_asset(AssetNode {
            asset_id: "w-ledger-db".to_string(),
            name: "Ledger Database".to_string(),
            namespace: "payments".to_string(),
            criticality: AssetCriticality::CrownJewel,
            is_cloud_metadata_service: false,
            is_k8s_api_server: false,
            is_database: true,
        });

        engine.blast_analyzer.add_dependency_edge(
            "w-payment-ingress",
            "w-ledger-db",
            "TCP",
            5432,
        );

        engine.blast_analyzer.add_dependency_edge(
            "w-payment-ingress",
            "infra:cloud-metadata",
            "HTTP",
            80,
        );

        // 2. Compromised inputs
        let inputs = WorkloadRiskInputs {
            anomaly_count: 6,
            mitre_critical_alerts: 3,
            critical_cve_count: 3,
            high_cve_count: 2,
            has_known_exploited_vulnerability: true,
            has_public_ingress: true,
            open_port_count: 5,
            connects_to_external_ips: true,
            is_privileged: true,
            runs_as_root: true,
            shares_host_network: true,
            shares_host_pid: false,
            dangerous_capabilities: vec!["CAP_NET_ADMIN".to_string()],
        };

        let (profile, blast, decision) = engine.assess_and_contain(
            "w-payment-ingress",
            "payment-pod",
            "payments",
            &inputs,
            2,
            1_000_000,
        );

        // Assert profile is critical
        assert_eq!(profile.tier, RiskTier::Critical);
        assert!(profile.composite_score >= 85.0);

        // Assert blast radius reaches crown jewel and metadata
        assert_eq!(blast.blast_severity, BlastSeverity::Catastrophic);
        assert!(blast.cloud_metadata_reachable);

        // Assert automated containment action triggered
        assert!(
            decision.action == ContainmentAction::NetworkQuarantine
                || decision.action == ContainmentAction::CgroupFreeze
        );
        assert_eq!(engine.containment_manager.total_triggered_count(), 1);
    }
}
