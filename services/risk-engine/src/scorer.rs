//! # Multi-Dimensional Workload Risk Scoring Engine
//!
//! Computes continuous, real-time risk scores (0–100) across all Kubernetes workloads.
//! Aggregates four distinct risk vectors:
//! 1. **Runtime Anomaly Vector**: Process execution anomalies, unexpected syscalls, and MITRE tactics.
//! 2. **Vulnerability (CVE) Vector**: Unpatched vulnerabilities, CVSS score distribution, and KEV flags.
//! 3. **Network Attack Surface Vector**: Public ingress, unauthenticated endpoints, and external egress.
//! 4. **Privilege & Configuration Vector**: Root execution, Linux capabilities, and host namespace sharing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Operational risk level category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskTier {
    Low,      // 0 - 29
    Medium,   // 30 - 59
    High,     // 60 - 84
    Critical, // 85 - 100
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Breakdown of individual threat scoring vectors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskVectors {
    /// Score from 0 to 25 based on runtime anomalies and MITRE alerts.
    pub runtime_anomaly_score: f64,
    /// Score from 0 to 25 based on SBOM CVE severities.
    pub vulnerability_score: f64,
    /// Score from 0 to 25 based on network surface exposure.
    pub network_surface_score: f64,
    /// Score from 0 to 25 based on container privilege and securityContext.
    pub privilege_score: f64,
}

/// Comprehensive risk assessment snapshot for a workload or pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadRiskProfile {
    pub workload_id: String,
    pub pod_name: String,
    pub namespace: String,
    pub composite_score: f64,
    pub tier: RiskTier,
    pub vectors: RiskVectors,
    pub evaluated_at_ns: u64,
    pub active_findings: Vec<String>,
}

/// Raw input parameters used to evaluate workload risk.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkloadRiskInputs {
    pub anomaly_count: u32,
    pub mitre_critical_alerts: u32,
    pub critical_cve_count: u32,
    pub high_cve_count: u32,
    pub has_known_exploited_vulnerability: bool,
    pub has_public_ingress: bool,
    pub open_port_count: u32,
    pub connects_to_external_ips: bool,
    pub is_privileged: bool,
    pub runs_as_root: bool,
    pub shares_host_network: bool,
    pub shares_host_pid: bool,
    pub dangerous_capabilities: Vec<String>,
}

/// Multi-Dimensional Workload Risk Scoring Engine.
pub struct WorkloadRiskScorer {
    profiles: Arc<RwLock<HashMap<String, WorkloadRiskProfile>>>,
    decay_rate_per_minute: f64,
    total_evaluations: AtomicU64,
}

impl Default for WorkloadRiskScorer {
    fn default() -> Self {
        Self::new(0.05) // 5% score decay per minute of benign activity
    }
}

impl WorkloadRiskScorer {
    /// Creates a new risk scorer with configurable benign activity decay rate.
    pub fn new(decay_rate_per_minute: f64) -> Self {
        Self {
            profiles: Arc::new(RwLock::new(HashMap::new())),
            decay_rate_per_minute,
            total_evaluations: AtomicU64::new(0),
        }
    }

    /// Evaluates raw workload indicators and produces an updated `WorkloadRiskProfile`.
    pub fn evaluate_workload(
        &self,
        workload_id: &str,
        pod_name: &str,
        namespace: &str,
        inputs: &WorkloadRiskInputs,
        timestamp_ns: u64,
    ) -> WorkloadRiskProfile {
        self.total_evaluations.fetch_add(1, Ordering::Relaxed);
        let mut findings = Vec::new();

        // 1. Runtime Anomaly Vector (Max 25 pts)
        let mut anomaly_score: f64 = 0.0;
        if inputs.anomaly_count > 0 {
            anomaly_score += (inputs.anomaly_count as f64 * 3.0).min(10.0);
            findings.push(format!(
                "{} runtime anomalies detected",
                inputs.anomaly_count
            ));
        }
        if inputs.mitre_critical_alerts > 0 {
            anomaly_score += (inputs.mitre_critical_alerts as f64 * 7.5).min(15.0);
            findings.push(format!(
                "{} MITRE ATT&CK critical security alerts",
                inputs.mitre_critical_alerts
            ));
        }
        anomaly_score = anomaly_score.min(25.0);

        // 2. Vulnerability / CVE Vector (Max 25 pts)
        let mut vuln_score: f64 = 0.0;
        if inputs.critical_cve_count > 0 {
            vuln_score += (inputs.critical_cve_count as f64 * 6.0).min(12.0);
            findings.push(format!(
                "{} Critical CVEs in container image",
                inputs.critical_cve_count
            ));
        }
        if inputs.high_cve_count > 0 {
            vuln_score += (inputs.high_cve_count as f64 * 2.0).min(8.0);
            findings.push(format!(
                "{} High severity CVEs in container image",
                inputs.high_cve_count
            ));
        }
        if inputs.has_known_exploited_vulnerability {
            vuln_score += 5.0;
            findings.push("Contains CISA Known Exploited Vulnerability (KEV)".to_string());
        }
        vuln_score = vuln_score.min(25.0);

        // 3. Network Attack Surface Vector (Max 25 pts)
        let mut net_score: f64 = 0.0;
        if inputs.has_public_ingress {
            net_score += 10.0;
            findings.push("Direct public ingress exposed to internet".to_string());
        }
        if inputs.connects_to_external_ips {
            net_score += 7.0;
            findings.push("Workload establishes outbound internet connections".to_string());
        }
        if inputs.open_port_count > 3 {
            net_score += (inputs.open_port_count as f64 * 1.5).min(8.0);
            findings.push(format!(
                "{} open listening ports exposed",
                inputs.open_port_count
            ));
        }
        net_score = net_score.min(25.0);

        // 4. Privilege & Configuration Vector (Max 25 pts)
        let mut priv_score: f64 = 0.0;
        if inputs.is_privileged {
            priv_score += 12.0;
            findings.push("Container runs with securityContext.privileged=true".to_string());
        }
        if inputs.runs_as_root {
            priv_score += 5.0;
            findings.push("Container executes as root UID 0".to_string());
        }
        if inputs.shares_host_network {
            priv_score += 4.0;
            findings.push("Workload shares host network namespace (hostNetwork=true)".to_string());
        }
        if inputs.shares_host_pid {
            priv_score += 4.0;
            findings.push("Workload shares host PID namespace (hostPID=true)".to_string());
        }
        if !inputs.dangerous_capabilities.is_empty() {
            priv_score = (priv_score + 5.0).min(25.0);
            findings.push(format!(
                "Elevated Linux capabilities: {:?}",
                inputs.dangerous_capabilities
            ));
        }
        priv_score = priv_score.min(25.0);

        let composite_score = (anomaly_score + vuln_score + net_score + priv_score).min(100.0);

        let tier = match composite_score as u32 {
            85..=100 => RiskTier::Critical,
            60..=84 => RiskTier::High,
            30..=59 => RiskTier::Medium,
            _ => RiskTier::Low,
        };

        let profile = WorkloadRiskProfile {
            workload_id: workload_id.to_string(),
            pod_name: pod_name.to_string(),
            namespace: namespace.to_string(),
            composite_score,
            tier,
            vectors: RiskVectors {
                runtime_anomaly_score: anomaly_score,
                vulnerability_score: vuln_score,
                network_surface_score: net_score,
                privilege_score: priv_score,
            },
            evaluated_at_ns: timestamp_ns,
            active_findings: findings,
        };

        let mut profiles = self.profiles.write().unwrap();
        profiles.insert(workload_id.to_string(), profile.clone());

        profile
    }

    /// Applies time-based benign activity score decay to an existing profile.
    pub fn apply_decay(
        &self,
        workload_id: &str,
        elapsed_minutes: f64,
    ) -> Option<WorkloadRiskProfile> {
        let mut profiles = self.profiles.write().unwrap();
        if let Some(profile) = profiles.get_mut(workload_id) {
            let decay_factor = (1.0 - self.decay_rate_per_minute).powf(elapsed_minutes);
            profile.composite_score = (profile.composite_score * decay_factor).max(0.0);
            profile.tier = match profile.composite_score as u32 {
                85..=100 => RiskTier::Critical,
                60..=84 => RiskTier::High,
                30..=59 => RiskTier::Medium,
                _ => RiskTier::Low,
            };
            return Some(profile.clone());
        }
        None
    }

    /// Returns the risk profile for a given workload.
    pub fn get_profile(&self, workload_id: &str) -> Option<WorkloadRiskProfile> {
        self.profiles.read().unwrap().get(workload_id).cloned()
    }

    /// Returns all tracked workload risk profiles sorted from highest to lowest risk.
    pub fn list_profiles_by_risk(&self) -> Vec<WorkloadRiskProfile> {
        let mut list: Vec<WorkloadRiskProfile> =
            self.profiles.read().unwrap().values().cloned().collect();
        list.sort_by(|a, b| b.composite_score.partial_cmp(&a.composite_score).unwrap());
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benign_workload_low_risk() {
        let scorer = WorkloadRiskScorer::default();
        let inputs = WorkloadRiskInputs::default(); // all clean

        let profile =
            scorer.evaluate_workload("w-clean", "nginx-pod", "default", &inputs, 1_000_000);

        assert_eq!(profile.composite_score, 0.0);
        assert_eq!(profile.tier, RiskTier::Low);
        assert!(profile.active_findings.is_empty());
    }

    #[test]
    fn test_compromised_privileged_workload_critical_risk() {
        let scorer = WorkloadRiskScorer::default();
        let inputs = WorkloadRiskInputs {
            anomaly_count: 5,
            mitre_critical_alerts: 2,
            critical_cve_count: 2,
            high_cve_count: 3,
            has_known_exploited_vulnerability: true,
            has_public_ingress: true,
            open_port_count: 4,
            connects_to_external_ips: true,
            is_privileged: true,
            runs_as_root: true,
            shares_host_network: true,
            shares_host_pid: true,
            dangerous_capabilities: vec!["CAP_SYS_ADMIN".to_string()],
        };

        let profile = scorer.evaluate_workload(
            "w-compromised",
            "bad-actor-pod",
            "production",
            &inputs,
            1_000_000,
        );

        assert!(profile.composite_score >= 85.0);
        assert_eq!(profile.tier, RiskTier::Critical);
        assert!(!profile.active_findings.is_empty());
    }

    #[test]
    fn test_risk_score_decay_over_time() {
        let scorer = WorkloadRiskScorer::new(0.10); // 10% decay per minute
        let inputs = WorkloadRiskInputs {
            anomaly_count: 2,
            mitre_critical_alerts: 1,
            ..Default::default()
        };

        let initial = scorer.evaluate_workload("w-decay-test", "pod-1", "test", &inputs, 1_000_000);
        assert!(initial.composite_score > 10.0);

        // After 10 minutes, score should significantly decay
        let decayed = scorer.apply_decay("w-decay-test", 10.0).unwrap();
        assert!(decayed.composite_score < initial.composite_score);
    }
}
