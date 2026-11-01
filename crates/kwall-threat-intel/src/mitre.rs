//! MITRE ATT&CK Matrix taxonomy for Kubernetes and container workloads.

use kwall_detection::alert::ThreatCategory;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MITRE ATT&CK Enterprise tactics relevant to cloud-native and container platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitreTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl MitreTactic {
    /// Formats the tactic into its official ATT&CK identifier (e.g., "TA0002").
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::InitialAccess => "TA0001",
            Self::Execution => "TA0002",
            Self::Persistence => "TA0003",
            Self::PrivilegeEscalation => "TA0004",
            Self::DefenseEvasion => "TA0005",
            Self::CredentialAccess => "TA0006",
            Self::Discovery => "TA0007",
            Self::LateralMovement => "TA0008",
            Self::Collection => "TA0009",
            Self::CommandAndControl => "TA0011",
            Self::Exfiltration => "TA0010",
            Self::Impact => "TA0040",
        }
    }

    /// Official human-readable display name.
    #[must_use]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::InitialAccess => "Initial Access",
            Self::Execution => "Execution",
            Self::Persistence => "Persistence",
            Self::PrivilegeEscalation => "Privilege Escalation",
            Self::DefenseEvasion => "Defense Evasion",
            Self::CredentialAccess => "Credential Access",
            Self::Discovery => "Discovery",
            Self::LateralMovement => "Lateral Movement",
            Self::Collection => "Collection",
            Self::CommandAndControl => "Command and Control",
            Self::Exfiltration => "Exfiltration",
            Self::Impact => "Impact",
        }
    }
}

/// A specific MITRE ATT&CK Technique or Sub-technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: MitreTactic,
    pub description: String,
    pub detection_guidance: String,
}

/// Registry storing MITRE ATT&CK matrix definitions for containers.
#[derive(Debug, Clone)]
pub struct MitreMatrix {
    techniques: HashMap<String, MitreTechnique>,
}

impl Default for MitreMatrix {
    fn default() -> Self {
        Self::new()
    }
}

impl MitreMatrix {
    /// Initializes the matrix populated with standard container security techniques.
    #[must_use]
    pub fn new() -> Self {
        let mut matrix = Self {
            techniques: HashMap::new(),
        };
        matrix.load_container_techniques();
        matrix
    }

    fn register(&mut self, id: &str, name: &str, tactic: MitreTactic, desc: &str, guidance: &str) {
        self.techniques.insert(
            id.to_string(),
            MitreTechnique {
                id: id.to_string(),
                name: name.to_string(),
                tactic,
                description: desc.to_string(),
                detection_guidance: guidance.to_string(),
            },
        );
    }

    /// Loads standard ATT&CK for Containers definitions.
    fn load_container_techniques(&mut self) {
        self.register(
            "T1611",
            "Escape to Host",
            MitreTactic::PrivilegeEscalation,
            "Adversaries may break out of a container to gain access to the underlying host.",
            "Monitor container namespace transitions, sysfs tampering, and docker/containerd socket access.",
        );
        self.register(
            "T1059.004",
            "Command and Scripting Interpreter: Unix Shell",
            MitreTactic::Execution,
            "Adversaries may abuse Unix shells to execute arbitrary commands within a container.",
            "Detect execution of /bin/sh, /bin/bash, /bin/dash, or interactive shells in production pods.",
        );
        self.register(
            "T1548",
            "Abuse Elevation Control Mechanism",
            MitreTactic::PrivilegeEscalation,
            "Adversaries may circumvent mechanisms designed to control elevation of privileges.",
            "Monitor setuid binary executions, sudo/su invocations, and Linux capability abuse.",
        );
        self.register(
            "T1552",
            "Unsecured Credentials",
            MitreTactic::CredentialAccess,
            "Adversaries may search container filesystems and secret mounts for passwords and API tokens.",
            "Alert on unexpected reads of /var/run/secrets/kubernetes.io/serviceaccount or /etc/shadow.",
        );
        self.register(
            "T1046",
            "Network Service Discovery",
            MitreTactic::Discovery,
            "Adversaries may scan Kubernetes cluster IP ranges to discover running services.",
            "Detect TCP/UDP connection bursts across multiple distinct destination ports.",
        );
        self.register(
            "T1021",
            "Remote Services",
            MitreTactic::LateralMovement,
            "Adversaries may move laterally between pods or into sensitive namespaces (e.g. kube-system).",
            "Enforce zero-trust network boundaries and alert on unauthorized inter-namespace traffic.",
        );
        self.register(
            "T1071",
            "Application Layer Protocol",
            MitreTactic::CommandAndControl,
            "Adversaries may communicate with C2 servers using application-layer protocols (HTTP, DNS).",
            "Inspect DNS queries for tunneling/DGA and detect outbound HTTP connections to known C2 feeds.",
        );
        self.register(
            "T1048",
            "Exfiltration Over Alternative Protocol",
            MitreTactic::Exfiltration,
            "Adversaries may steal data by exfiltrating it over unauthorized egress channels.",
            "Track high-volume egress anomalies and unauthorized public IP destination flows.",
        );
        self.register(
            "T1496",
            "Resource Hijacking",
            MitreTactic::Impact,
            "Adversaries may leverage container CPU and GPU resources to mine cryptocurrency.",
            "Detect abnormal CPU spikes, stratum mining protocol traffic, or known mining pool IPs.",
        );
        self.register(
            "T1562",
            "Impair Defenses",
            MitreTactic::DefenseEvasion,
            "Adversaries may disable security monitoring tools, audit daemons, or eBPF probes.",
            "Supervise BPF program attachment and alert on unauthorized detachment or SIGKILL signals.",
        );
        self.register(
            "T1190",
            "Exploit Public-Facing Application",
            MitreTactic::InitialAccess,
            "Adversaries may exploit vulnerabilities (SQLi, Log4Shell, RCE) in container web workloads.",
            "Inspect HTTP stream headers and payloads for known exploit patterns and deserialization attacks.",
        );
        self.register(
            "T1525",
            "Implant Internal Image",
            MitreTactic::Persistence,
            "Adversaries may deploy container images with backdoors or unverified provenance.",
            "Verify image cryptographic signatures with Cosign/Sigstore and enforce SBOM provenance.",
        );
    }

    /// Looks up a technique by its ATT&CK ID.
    #[must_use]
    pub fn get_technique(&self, id: &str) -> Option<&MitreTechnique> {
        self.techniques.get(id)
    }

    /// Maps a KWALL ThreatCategory to its default MITRE ATT&CK technique ID.
    #[must_use]
    pub fn map_category_to_technique(category: ThreatCategory) -> &'static str {
        match category {
            ThreatCategory::InteractiveShell => "T1059.004",
            ThreatCategory::ContainerEscape => "T1611",
            ThreatCategory::PrivilegeEscalation => "T1548",
            ThreatCategory::SensitiveFileAccess => "T1552",
            ThreatCategory::NetworkScan => "T1046",
            ThreatCategory::LateralMovement => "T1021",
            ThreatCategory::DataExfiltration => "T1048",
            ThreatCategory::BehavioralAnomaly => "T1204",
            ThreatCategory::DnsTunneling
            | ThreatCategory::DgaDomain
            | ThreatCategory::DnsResolverBypass => "T1071",
            ThreatCategory::HttpAttack => "T1190",
            ThreatCategory::TlsFingerprintAnomaly => "T1071",
            ThreatCategory::SbomDrift | ThreatCategory::FileIntegrityViolation => "T1562",
            ThreatCategory::ImageProvenanceViolation => "T1525",
            ThreatCategory::TopologyAnomaly => "T1021",
            ThreatCategory::ThreatIntelMatch => "T1071",
            ThreatCategory::SigmaRuleMatch => "T1059.004",
        }
    }

    /// Returns all registered techniques.
    #[must_use]
    pub fn all_techniques(&self) -> Vec<&MitreTechnique> {
        self.techniques.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitre_matrix_lookup_and_mapping() {
        let matrix = MitreMatrix::new();

        let t1611 = matrix.get_technique("T1611");
        assert!(t1611.is_some());
        assert_eq!(t1611.unwrap().name, "Escape to Host");
        assert_eq!(t1611.unwrap().tactic, MitreTactic::PrivilegeEscalation);

        let mapped = MitreMatrix::map_category_to_technique(ThreatCategory::ContainerEscape);
        assert_eq!(mapped, "T1611");

        let mapped_shell = MitreMatrix::map_category_to_technique(ThreatCategory::InteractiveShell);
        assert_eq!(mapped_shell, "T1059.004");
    }
}
