//! # Automated Risk-Based Containment Trigger
//!
//! Automatically initiates proactive incident response and workload containment
//! when a workload's risk score or lateral movement blast radius breaches critical thresholds.
//! Triggers network quarantine, cgroup freeze, or process termination without requiring
//! human operator intervention.

use crate::blast_radius::{BlastRadiusReport, BlastSeverity};
use crate::scorer::{RiskTier, WorkloadRiskProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Automated security containment action to apply to a compromised workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentAction {
    /// No active mitigation; audit and log.
    None,
    /// Alert security operations team.
    AlertOnly,
    /// Restrict egress to internal cluster subnets only.
    EgressRestriction,
    /// Apply immediate eBPF XDP/TC network quarantine (drop all traffic except agent).
    NetworkQuarantine,
    /// Pause all processes using Linux cgroup freezer controller (`cgroup.freeze`).
    CgroupFreeze,
    /// Terminate rogue pod immediately.
    TerminateWorkload,
}

impl std::fmt::Display for ContainmentAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::AlertOnly => write!(f, "ALERT_ONLY"),
            Self::EgressRestriction => write!(f, "EGRESS_RESTRICTION"),
            Self::NetworkQuarantine => write!(f, "NETWORK_QUARANTINE"),
            Self::CgroupFreeze => write!(f, "CGROUP_FREEZE"),
            Self::TerminateWorkload => write!(f, "TERMINATE_WORKLOAD"),
        }
    }
}

/// Decision receipt documenting an automated containment trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentDecision {
    pub decision_id: String,
    pub workload_id: String,
    pub pod_name: String,
    pub namespace: String,
    pub action: ContainmentAction,
    pub triggered_by_risk_score: f64,
    pub blast_severity: BlastSeverity,
    pub justification: String,
    pub executed_at_ns: u64,
    pub is_automatic: bool,
}

/// Configuration policy dictating automated containment thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentPolicy {
    /// Score threshold (e.g. 85.0) to trigger immediate network quarantine.
    pub quarantine_score_threshold: f64,
    /// Score threshold (e.g. 95.0) to freeze container cgroup.
    pub cgroup_freeze_threshold: f64,
    /// Automatically quarantine if cloud metadata service (169.254.169.254) is reachable.
    pub quarantine_on_cloud_metadata_exposure: bool,
    /// Automatically quarantine if Kubernetes API server is in lateral reach.
    pub quarantine_on_k8s_api_exposure: bool,
    pub auto_contain_enabled: bool,
}

impl Default for ContainmentPolicy {
    fn default() -> Self {
        Self {
            quarantine_score_threshold: 80.0,
            cgroup_freeze_threshold: 90.0,
            quarantine_on_cloud_metadata_exposure: true,
            quarantine_on_k8s_api_exposure: true,
            auto_contain_enabled: true,
        }
    }
}

/// Automated Risk-Based Containment Trigger Manager.
pub struct ContainmentTriggerManager {
    policy: Arc<RwLock<ContainmentPolicy>>,
    decisions_history: Arc<RwLock<Vec<ContainmentDecision>>>,
    active_containments: Arc<RwLock<HashMap<String, ContainmentDecision>>>,
    total_triggered: AtomicU64,
}

impl Default for ContainmentTriggerManager {
    fn default() -> Self {
        Self::new(ContainmentPolicy::default())
    }
}

impl ContainmentTriggerManager {
    /// Constructs a manager with explicit policy settings.
    pub fn new(policy: ContainmentPolicy) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            decisions_history: Arc::new(RwLock::new(Vec::new())),
            active_containments: Arc::new(RwLock::new(HashMap::new())),
            total_triggered: AtomicU64::new(0),
        }
    }

    /// Evaluates workload risk profile and blast radius to decide on automated containment.
    pub fn evaluate_containment(
        &self,
        profile: &WorkloadRiskProfile,
        blast: &BlastRadiusReport,
        timestamp_ns: u64,
    ) -> ContainmentDecision {
        let policy = self.policy.read().unwrap();

        let mut action = ContainmentAction::None;
        let mut reasons = Vec::new();

        if policy.auto_contain_enabled {
            if profile.composite_score >= policy.cgroup_freeze_threshold
                && blast.blast_severity == BlastSeverity::Catastrophic
            {
                action = ContainmentAction::CgroupFreeze;
                reasons.push(format!(
                    "Critical risk score ({:.1} >= {:.1}) and Catastrophic blast radius",
                    profile.composite_score, policy.cgroup_freeze_threshold
                ));
            } else if profile.composite_score >= policy.quarantine_score_threshold {
                action = ContainmentAction::NetworkQuarantine;
                reasons.push(format!(
                    "Risk score ({:.1} >= {:.1}) breaches quarantine threshold",
                    profile.composite_score, policy.quarantine_score_threshold
                ));
            } else if policy.quarantine_on_cloud_metadata_exposure && blast.cloud_metadata_reachable
            {
                action = ContainmentAction::NetworkQuarantine;
                reasons.push("Blast radius exposes Cloud Metadata (169.254.169.254)".to_string());
            } else if policy.quarantine_on_k8s_api_exposure && blast.k8s_api_server_reachable {
                action = ContainmentAction::EgressRestriction;
                reasons.push("Blast radius exposes Kubernetes API server".to_string());
            } else if profile.tier >= RiskTier::Medium {
                action = ContainmentAction::AlertOnly;
                reasons.push(format!("Workload in {} risk tier", profile.tier));
            }
        }

        let justification = if reasons.is_empty() {
            "Workload within benign operating boundaries".to_string()
        } else {
            reasons.join(" | ")
        };

        let decision = ContainmentDecision {
            decision_id: format!("dec-{}", timestamp_ns),
            workload_id: profile.workload_id.clone(),
            pod_name: profile.pod_name.clone(),
            namespace: profile.namespace.clone(),
            action,
            triggered_by_risk_score: profile.composite_score,
            blast_severity: blast.blast_severity,
            justification,
            executed_at_ns: timestamp_ns,
            is_automatic: policy.auto_contain_enabled,
        };

        if action != ContainmentAction::None && action != ContainmentAction::AlertOnly {
            self.total_triggered.fetch_add(1, Ordering::Relaxed);
            let mut active = self.active_containments.write().unwrap();
            active.insert(profile.workload_id.clone(), decision.clone());
        }

        let mut history = self.decisions_history.write().unwrap();
        if history.len() >= 10_000 {
            history.remove(0);
        }
        history.push(decision.clone());

        decision
    }

    /// Releases a workload from active containment.
    pub fn release_containment(&self, workload_id: &str) -> Option<ContainmentDecision> {
        let mut active = self.active_containments.write().unwrap();
        active.remove(workload_id)
    }

    /// Lists all currently quarantined or contained workloads.
    pub fn list_active_containments(&self) -> Vec<ContainmentDecision> {
        self.active_containments
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Returns the total number of containment actions triggered.
    pub fn total_triggered_count(&self) -> u64 {
        self.total_triggered.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scorer::RiskVectors;

    fn sample_profile(score: f64) -> WorkloadRiskProfile {
        let tier = match score as u32 {
            85..=100 => RiskTier::Critical,
            60..=84 => RiskTier::High,
            30..=59 => RiskTier::Medium,
            _ => RiskTier::Low,
        };

        WorkloadRiskProfile {
            workload_id: "w-test-1".to_string(),
            pod_name: "test-pod".to_string(),
            namespace: "prod".to_string(),
            composite_score: score,
            tier,
            vectors: RiskVectors::default(),
            evaluated_at_ns: 1_000_000,
            active_findings: Vec::new(),
        }
    }

    fn sample_blast(cloud_metadata: bool, severity: BlastSeverity) -> BlastRadiusReport {
        BlastRadiusReport {
            origin_workload_id: "w-test-1".to_string(),
            max_hops: 2,
            total_reachable_assets: 3,
            reachable_crown_jewels: Vec::new(),
            cloud_metadata_reachable: cloud_metadata,
            k8s_api_server_reachable: false,
            blast_severity: severity,
            movement_paths: Vec::new(),
            analyzed_at_ns: 1_000_000,
        }
    }

    #[test]
    fn test_quarantine_triggered_on_high_score() {
        let manager = ContainmentTriggerManager::default();
        let profile = sample_profile(82.0); // > 80.0
        let blast = sample_blast(false, BlastSeverity::Moderate);

        let decision = manager.evaluate_containment(&profile, &blast, 1_000_000);
        assert_eq!(decision.action, ContainmentAction::NetworkQuarantine);
        assert_eq!(manager.total_triggered_count(), 1);
        assert_eq!(manager.list_active_containments().len(), 1);
    }

    #[test]
    fn test_cgroup_freeze_on_critical_score_and_catastrophic_blast() {
        let manager = ContainmentTriggerManager::default();
        let profile = sample_profile(95.0); // > 90.0
        let blast = sample_blast(true, BlastSeverity::Catastrophic);

        let decision = manager.evaluate_containment(&profile, &blast, 2_000_000);
        assert_eq!(decision.action, ContainmentAction::CgroupFreeze);
        assert!(decision.justification.contains("Catastrophic"));
    }

    #[test]
    fn test_metadata_exposure_triggers_quarantine() {
        let manager = ContainmentTriggerManager::default();
        let profile = sample_profile(40.0); // score < 80.0
        let blast = sample_blast(true, BlastSeverity::Severe); // but cloud metadata reachable!

        let decision = manager.evaluate_containment(&profile, &blast, 3_000_000);
        assert_eq!(decision.action, ContainmentAction::NetworkQuarantine);
        assert!(decision.justification.contains("169.254.169.254"));
    }
}
