//! MITRE ATT&CK coverage tracking and compliance heatmap generation.

use crate::mitre::{MitreMatrix, MitreTactic};
use kwall_detection::alert::ThreatAlert;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Coverage metrics for a specific MITRE ATT&CK tactic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic_id: String,
    pub tactic_name: String,
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_pct: f64,
    pub active_alert_hits: usize,
}

/// A comprehensive MITRE ATT&CK compliance and coverage posture report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceHeatmapReport {
    pub cluster_id: String,
    pub generated_at_ns: u64,
    pub overall_coverage_pct: f64,
    pub total_alerts_recorded: usize,
    pub tactic_coverages: Vec<TacticCoverage>,
    pub technique_hits: HashMap<String, usize>,
}

impl ComplianceHeatmapReport {
    /// Formats the compliance heatmap report as a Markdown document.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# KWALL — MITRE ATT&CK Container Security Posture\n\n");
        md.push_str(&format!("- **Cluster**: `{}`\n", self.cluster_id));
        md.push_str(&format!(
            "- **Overall Coverage**: `{:.1}%`\n",
            self.overall_coverage_pct
        ));
        md.push_str(&format!(
            "- **Active Threat Alerts**: `{}`\n\n",
            self.total_alerts_recorded
        ));

        md.push_str("### Tactic Coverage Matrix\n\n");
        md.push_str("| ID | Tactic | Covered Techniques | Coverage % | Alert Hits | Status |\n");
        md.push_str("|---|---|---|---|---|---|\n");

        for tc in &self.tactic_coverages {
            let status = if tc.coverage_pct >= 80.0 {
                "🟢 Strong"
            } else if tc.coverage_pct >= 50.0 {
                "🟡 Moderate"
            } else {
                "🔴 Deficient"
            };

            md.push_str(&format!(
                "| `{}` | {} | {} / {} | `{:.1}%` | {} | {} |\n",
                tc.tactic_id,
                tc.tactic_name,
                tc.covered_techniques,
                tc.total_techniques,
                tc.coverage_pct,
                tc.active_alert_hits,
                status
            ));
        }

        md.push_str("\n### Top Technique Detection Hits\n\n");
        md.push_str("| Technique ID | Triggered Alert Count |\n");
        md.push_str("|---|---|\n");

        let mut hits: Vec<(&String, &usize)> = self.technique_hits.iter().collect();
        hits.sort_by(|a, b| b.1.cmp(a.1));

        if hits.is_empty() {
            md.push_str("| *None* | 0 |\n");
        } else {
            for (tech, count) in hits.iter().take(10) {
                md.push_str(&format!("| `{}` | {} |\n", tech, count));
            }
        }

        md
    }
}

/// Thread-safe tracker computing MITRE ATT&CK coverage and active alert heatmaps.
pub struct MitreComplianceTracker {
    matrix: MitreMatrix,
    covered_techniques: RwLock<HashSet<String>>,
    alert_hits: RwLock<HashMap<String, usize>>,
}

impl Default for MitreComplianceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MitreComplianceTracker {
    /// Creates a new MitreComplianceTracker initialized with default coverage.
    #[must_use]
    pub fn new() -> Self {
        let matrix = MitreMatrix::new();
        let mut covered = HashSet::new();

        // Populate covered techniques enabled out-of-the-box by KWALL
        for tech in matrix.all_techniques() {
            covered.insert(tech.id.clone());
        }

        Self {
            matrix,
            covered_techniques: RwLock::new(covered),
            alert_hits: RwLock::new(HashMap::new()),
        }
    }

    /// Records an alert to increment technique hit metrics.
    pub fn record_alert(&self, alert: &ThreatAlert) {
        let tech_id = alert
            .mitre_attack_id
            .clone()
            .unwrap_or_else(|| MitreMatrix::map_category_to_technique(alert.category).to_string());

        let mut hits = self.alert_hits.write().unwrap();
        *hits.entry(tech_id).or_insert(0) += 1;
    }

    /// Manually sets whether a specific technique is considered covered by active policy.
    pub fn set_technique_covered(&self, technique_id: &str, covered: bool) {
        let mut set = self.covered_techniques.write().unwrap();
        if covered {
            set.insert(technique_id.to_string());
        } else {
            set.remove(technique_id);
        }
    }

    /// Generates a complete ComplianceHeatmapReport.
    #[must_use]
    pub fn generate_report(&self, cluster_id: &str, timestamp_ns: u64) -> ComplianceHeatmapReport {
        let covered = self.covered_techniques.read().unwrap();
        let hits = self.alert_hits.read().unwrap();

        let tactics = [
            MitreTactic::InitialAccess,
            MitreTactic::Execution,
            MitreTactic::Persistence,
            MitreTactic::PrivilegeEscalation,
            MitreTactic::DefenseEvasion,
            MitreTactic::CredentialAccess,
            MitreTactic::Discovery,
            MitreTactic::LateralMovement,
            MitreTactic::Collection,
            MitreTactic::CommandAndControl,
            MitreTactic::Exfiltration,
            MitreTactic::Impact,
        ];

        let mut tactic_coverages = Vec::new();
        let mut total_techniques_count = 0;
        let mut total_covered_count = 0;
        let mut total_alerts_recorded = 0;

        for tactic in tactics {
            let techniques: Vec<_> = self
                .matrix
                .all_techniques()
                .into_iter()
                .filter(|t| t.tactic == tactic)
                .collect();

            let total_t = techniques.len();
            let covered_t = techniques
                .iter()
                .filter(|t| covered.contains(&t.id))
                .count();

            let mut active_hits = 0;
            for t in &techniques {
                if let Some(&count) = hits.get(&t.id) {
                    active_hits += count;
                }
            }

            total_techniques_count += total_t;
            total_covered_count += covered_t;
            total_alerts_recorded += active_hits;

            let coverage_pct = if total_t == 0 {
                100.0
            } else {
                (covered_t as f64 / total_t as f64) * 100.0
            };

            tactic_coverages.push(TacticCoverage {
                tactic_id: tactic.id().to_string(),
                tactic_name: tactic.display_name().to_string(),
                total_techniques: total_t,
                covered_techniques: covered_t,
                coverage_pct,
                active_alert_hits: active_hits,
            });
        }

        let overall_coverage_pct = if total_techniques_count == 0 {
            100.0
        } else {
            (total_covered_count as f64 / total_techniques_count as f64) * 100.0
        };

        ComplianceHeatmapReport {
            cluster_id: cluster_id.to_string(),
            generated_at_ns: timestamp_ns,
            overall_coverage_pct,
            total_alerts_recorded,
            tactic_coverages,
            technique_hits: hits.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::Severity;
    use kwall_detection::alert::ThreatCategory;

    #[test]
    fn test_compliance_tracker_and_heatmap_report() {
        let tracker = MitreComplianceTracker::new();

        let alert = ThreatAlert {
            alert_id: "test-alert-1".to_string(),
            timestamp_ns: 1_000_000,
            severity: Severity::Critical,
            category: ThreatCategory::ContainerEscape,
            mitre_attack_id: Some("T1611".to_string()),
            title: "Container escape detected".to_string(),
            description: "Breakout attempt".to_string(),
            workload: None,
            evidence: serde_json::json!({}),
            recommended_action: "Quarantine".to_string(),
        };

        tracker.record_alert(&alert);

        let report = tracker.generate_report("prod-cluster-us-east", 1_000_000);
        assert_eq!(report.cluster_id, "prod-cluster-us-east");
        assert!(report.overall_coverage_pct > 80.0);
        assert_eq!(report.total_alerts_recorded, 1);
        assert_eq!(*report.technique_hits.get("T1611").unwrap(), 1);

        let md = report.to_markdown();
        assert!(md.contains("prod-cluster-us-east"));
        assert!(md.contains("T1611"));
    }
}
