//! Security Threat Alert definitions and MITRE ATT&CK taxonomy.

use kwall_core::types::Severity;
use kwall_event_enricher::enricher::EnrichedWorkloadContext;
use serde::{Deserialize, Serialize};

/// High-level categorization of container and network security threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    /// Interactive or unexpected shells executed in containers.
    InteractiveShell,
    /// Attempts to escape container confinement or tamper with host kernel/cgroups.
    ContainerEscape,
    /// Unauthorized privilege escalation (setuid, capability abuse).
    PrivilegeEscalation,
    /// Unauthorized access to credentials, tokens, or cryptographic keys.
    SensitiveFileAccess,
    /// Network scanning or port sweep behaviors.
    NetworkScan,
    /// Unauthorized lateral communication across service boundaries.
    LateralMovement,
    /// Unusual outbound data transfer volume or destinations.
    DataExfiltration,
    /// Deviation from learned workload behavioral baseline.
    BehavioralAnomaly,
    /// DNS covert channel / exfiltration via tunneling.
    DnsTunneling,
    /// Domain Generation Algorithm generated domain query.
    DgaDomain,
    /// DNS query bypassing authorized cluster resolvers.
    DnsResolverBypass,
    /// Web application attack signature detected (SQLi, XSS, Log4Shell, Path Traversal).
    HttpAttack,
    /// Malicious or unauthorized TLS JA3/JA4 client fingerprint.
    TlsFingerprintAnomaly,
    /// Runtime binary execution not present in declared container SBOM.
    SbomDrift,
    /// Unauthorized modification or tampering with protected binaries/files (FIM).
    FileIntegrityViolation,
    /// Container image signature or provenance policy violation.
    ImageProvenanceViolation,
    /// Unprecedented service-to-service communication edge or topology anomaly.
    TopologyAnomaly,
    /// Known malicious indicator match from threat intelligence feeds (C2, malware IP, domain, hash).
    ThreatIntelMatch,
    /// Detection matching an active Sigma detection rule.
    SigmaRuleMatch,
}

/// A structured, non-repudiable security alert produced by the KWALL detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    /// Unique identifier for this alert instance.
    pub alert_id: String,
    /// Nanosecond timestamp when the detection occurred.
    pub timestamp_ns: u64,
    /// Severity classification.
    pub severity: Severity,
    /// Threat category.
    pub category: ThreatCategory,
    /// MITRE ATT&CK technique ID (e.g., "T1059.004", "T1611", "T1046").
    pub mitre_attack_id: Option<String>,
    /// Concise human-readable title.
    pub title: String,
    /// In-depth diagnostic details and rationale.
    pub description: String,
    /// Workload contextual metadata, if correlated.
    pub workload: Option<EnrichedWorkloadContext>,
    /// Structured forensic evidence attributes.
    pub evidence: serde_json::Value,
    /// Recommended immediate remediation or response action.
    pub recommended_action: String,
}

impl ThreatAlert {
    /// Creates a new ThreatAlert with generated timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        alert_id: String,
        timestamp_ns: u64,
        severity: Severity,
        category: ThreatCategory,
        mitre_attack_id: Option<&str>,
        title: impl Into<String>,
        description: impl Into<String>,
        workload: Option<EnrichedWorkloadContext>,
        evidence: serde_json::Value,
        recommended_action: impl Into<String>,
    ) -> Self {
        Self {
            alert_id,
            timestamp_ns,
            severity,
            category,
            mitre_attack_id: mitre_attack_id.map(ToString::to_string),
            title: title.into(),
            description: description.into(),
            workload,
            evidence,
            recommended_action: recommended_action.into(),
        }
    }
}
