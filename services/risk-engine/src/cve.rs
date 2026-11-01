//! # CVE Risk Prioritization & CVSS Scoring Bridge
//!
//! Maps SBOM-derived CVE findings to structured risk inputs for the workload risk scorer.
//! Implements CVSS v3.1 severity banding and CISA KEV integration to compute the
//! aggregated vulnerability attack surface for a container workload.

use serde::{Deserialize, Serialize};

/// CVSS v3.1 base severity classifications per NVD definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CvssSeverity {
    None,     // CVSS 0.0
    Low,      // CVSS 0.1 – 3.9
    Medium,   // CVSS 4.0 – 6.9
    High,     // CVSS 7.0 – 8.9
    Critical, // CVSS 9.0 – 10.0
}

impl CvssSeverity {
    /// Converts a CVSS v3.1 numeric base score to a severity band.
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::None,
        }
    }
}

impl std::fmt::Display for CvssSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "NONE"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single CVE finding from an SBOM scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveFinding {
    /// CVE identifier (e.g. `CVE-2021-44228`).
    pub cve_id: String,
    /// CVSS v3.1 base score (0.0 – 10.0).
    pub cvss_score: f64,
    /// Derived severity band.
    pub severity: CvssSeverity,
    /// Whether the CVE appears in the CISA Known Exploited Vulnerabilities (KEV) catalog.
    pub is_known_exploited: bool,
    /// Affected package name within the container image.
    pub package_name: String,
    /// Installed package version containing the vulnerability.
    pub installed_version: String,
    /// Earliest patched version, if known.
    pub fixed_version: Option<String>,
}

impl CveFinding {
    /// Constructs a new CVE finding, auto-deriving the severity band from the CVSS score.
    pub fn new(
        cve_id: impl Into<String>,
        cvss_score: f64,
        is_known_exploited: bool,
        package_name: impl Into<String>,
        installed_version: impl Into<String>,
        fixed_version: Option<String>,
    ) -> Self {
        Self {
            cve_id: cve_id.into(),
            severity: CvssSeverity::from_score(cvss_score),
            cvss_score,
            is_known_exploited,
            package_name: package_name.into(),
            installed_version: installed_version.into(),
            fixed_version,
        }
    }
}

/// Aggregated CVE posture computed from a set of scan findings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CveRiskSummary {
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub has_known_exploited: bool,
    /// The highest CVSS score across all findings.
    pub max_cvss_score: f64,
}

/// Aggregates a slice of CVE findings into a `CveRiskSummary`.
pub fn aggregate_cve_findings(findings: &[CveFinding]) -> CveRiskSummary {
    let mut summary = CveRiskSummary::default();
    for f in findings {
        if f.is_known_exploited {
            summary.has_known_exploited = true;
        }
        if f.cvss_score > summary.max_cvss_score {
            summary.max_cvss_score = f.cvss_score;
        }
        match f.severity {
            CvssSeverity::Critical => summary.critical_count += 1,
            CvssSeverity::High => summary.high_count += 1,
            CvssSeverity::Medium => summary.medium_count += 1,
            CvssSeverity::Low => summary.low_count += 1,
            CvssSeverity::None => {}
        }
    }
    summary
}

/// Converts a `CveRiskSummary` into the CVE-related fields of `WorkloadRiskInputs`
/// for direct consumption by `WorkloadRiskScorer::evaluate_workload`.
///
/// Returns `(critical_cve_count, high_cve_count, has_known_exploited)`.
pub fn summary_to_scorer_inputs(summary: &CveRiskSummary) -> (u32, u32, bool) {
    (
        summary.critical_count,
        summary.high_count,
        summary.has_known_exploited,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_severity_banding() {
        assert_eq!(CvssSeverity::from_score(9.8), CvssSeverity::Critical);
        assert_eq!(CvssSeverity::from_score(7.0), CvssSeverity::High);
        assert_eq!(CvssSeverity::from_score(5.5), CvssSeverity::Medium);
        assert_eq!(CvssSeverity::from_score(2.1), CvssSeverity::Low);
        assert_eq!(CvssSeverity::from_score(0.0), CvssSeverity::None);
    }

    #[test]
    fn test_aggregate_cve_findings_log4shell() {
        // Simulate Log4Shell (CVE-2021-44228) + several high/medium CVEs.
        let findings = vec![
            CveFinding::new(
                "CVE-2021-44228",
                10.0,
                true,
                "log4j-core",
                "2.14.1",
                Some("2.17.1".to_string()),
            ),
            CveFinding::new(
                "CVE-2022-22965",
                9.8,
                true,
                "spring-core",
                "5.3.17",
                Some("5.3.18".to_string()),
            ),
            CveFinding::new(
                "CVE-2023-1234",
                7.5,
                false,
                "openssl",
                "1.1.1q",
                Some("1.1.1t".to_string()),
            ),
            CveFinding::new("CVE-2023-5678", 4.3, false, "curl", "7.88.0", None),
        ];

        let summary = aggregate_cve_findings(&findings);

        assert_eq!(summary.critical_count, 2);
        assert_eq!(summary.high_count, 1);
        assert_eq!(summary.medium_count, 1);
        assert!(summary.has_known_exploited);
        assert_eq!(summary.max_cvss_score, 10.0);
    }

    #[test]
    fn test_summary_to_scorer_inputs() {
        let summary = CveRiskSummary {
            critical_count: 3,
            high_count: 5,
            has_known_exploited: true,
            ..Default::default()
        };
        let (crit, high, kev) = summary_to_scorer_inputs(&summary);
        assert_eq!(crit, 3);
        assert_eq!(high, 5);
        assert!(kev);
    }

    #[test]
    fn test_clean_image_zero_cves() {
        let findings: Vec<CveFinding> = vec![];
        let summary = aggregate_cve_findings(&findings);
        assert_eq!(summary.critical_count, 0);
        assert_eq!(summary.high_count, 0);
        assert!(!summary.has_known_exploited);
        assert_eq!(summary.max_cvss_score, 0.0);
    }
}
