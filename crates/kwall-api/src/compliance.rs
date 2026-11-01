//! Automated Compliance Reporting Engine.
//!
//! Evaluates active eBPF security controls, LSM sandboxing, and policy enforcements
//! against enterprise compliance standards:
//! - CIS Kubernetes Benchmark v1.8
//! - SOC 2 Type II Trust Services Criteria (Security & Confidentiality)
//! - PCI-DSS v4.0 Network Security & File Integrity Monitoring (FIM)

use serde::{Deserialize, Serialize};

/// Supported regulatory compliance frameworks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    CisKubernetesV1_8,
    Soc2Type2,
    PciDssV4_0,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CisKubernetesV1_8 => write!(f, "CIS-Kubernetes-v1.8"),
            Self::Soc2Type2 => write!(f, "SOC2-Type-II"),
            Self::PciDssV4_0 => write!(f, "PCI-DSS-v4.0"),
        }
    }
}

/// Status of an individual control evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Passed,
    Warning,
    Failed,
    NotApplicable,
}

impl std::fmt::Display for ControlStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passed => write!(f, "PASSED"),
            Self::Warning => write!(f, "WARNING"),
            Self::Failed => write!(f, "FAILED"),
            Self::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// An individual audited control requirement and its evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvaluation {
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub status: ControlStatus,
    pub evidence: String,
    pub remediation: Option<String>,
}

/// Comprehensive compliance evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: ComplianceFramework,
    pub cluster_id: String,
    pub timestamp_ns: u64,
    pub score_percent: f64,
    pub total_controls: usize,
    pub passed_controls: usize,
    pub warning_controls: usize,
    pub failed_controls: usize,
    pub evaluations: Vec<ControlEvaluation>,
}

impl ComplianceReport {
    /// Formats the compliance report as a clean human-readable scorecard.
    pub fn generate_scorecard(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "================================================================================\n\
             KWALL ENTERPRISE COMPLIANCE SCORECARD: {}\n\
             Cluster: {} | Generated: {} ns\n\
             Overall Compliance Score: {:.1}%\n\
             Results: {} Passed | {} Warnings | {} Failed (Total: {})\n\
             ================================================================================\n",
            self.framework,
            self.cluster_id,
            self.timestamp_ns,
            self.score_percent,
            self.passed_controls,
            self.warning_controls,
            self.failed_controls,
            self.total_controls
        ));

        for c in &self.evaluations {
            let icon = match c.status {
                ControlStatus::Passed => "[PASS]",
                ControlStatus::Warning => "[WARN]",
                ControlStatus::Failed => "[FAIL]",
                ControlStatus::NotApplicable => "[N/A ]",
            };
            out.push_str(&format!(
                "{:<7} {:<12} {}\n        Evidence: {}\n",
                icon, c.control_id, c.title, c.evidence
            ));
            if let Some(ref rem) = c.remediation {
                out.push_str(&format!("        Remediation: {}\n", rem));
            }
        }
        out.push_str(
            "================================================================================\n",
        );
        out
    }

    /// Exports the report as a structured JSON Value.
    pub fn export_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Engine for evaluating cluster state against compliance frameworks.
pub struct ComplianceEngine;

impl ComplianceEngine {
    /// Evaluates the cluster against the CIS Kubernetes Benchmark v1.8.
    pub fn evaluate_cis(
        cluster_id: &str,
        timestamp_ns: u64,
        lsm_active: bool,
        fim_active: bool,
        xdp_egress_restricted: bool,
        auditd_ingestion_healthy: bool,
    ) -> ComplianceReport {
        let mut evals = Vec::new();

        // CIS 5.2.1: Host file integrity and LSM binary restriction
        evals.push(ControlEvaluation {
            control_id: "CIS-5.2.1".to_string(),
            title: "Kernel LSM Binary Execution & File Integrity".to_string(),
            description: "Restrict unauthorized binaries and protect sensitive files via bpf_lsm"
                .to_string(),
            status: if lsm_active {
                ControlStatus::Passed
            } else {
                ControlStatus::Failed
            },
            evidence: if lsm_active {
                "bpf_lsm hooks bprm_check_security and file_open active on all worker nodes"
                    .to_string()
            } else {
                "eBPF LSM hooks are not loaded or kernel does not support BPF_PROG_TYPE_LSM"
                    .to_string()
            },
            remediation: if !lsm_active {
                Some(
                    "Enable lsm=bpf,apparmor in GRUB cmdline and restart kwall-node-agent"
                        .to_string(),
                )
            } else {
                None
            },
        });

        // CIS 5.3.2: FIM monitoring of /etc/kubernetes and host binaries
        evals.push(ControlEvaluation {
            control_id: "CIS-5.3.2".to_string(),
            title: "File Integrity Monitoring for Control Plane Manifests".to_string(),
            description: "Monitor manifest and crypto changes via eBPF inode notifications"
                .to_string(),
            status: if fim_active {
                ControlStatus::Passed
            } else {
                ControlStatus::Failed
            },
            evidence: if fim_active {
                "eBPF FIM tracking inode modifications across /etc/kubernetes and /var/lib/kubelet"
                    .to_string()
            } else {
                "FIM module disabled or watch directory unmounted".to_string()
            },
            remediation: None,
        });

        // CIS 5.4.1: Pod network isolation
        evals.push(ControlEvaluation {
            control_id: "CIS-5.4.1".to_string(),
            title: "Network Policy Ingress/Egress Isolation".to_string(),
            description: "Default-deny network policies enforced at XDP/TC layer".to_string(),
            status: if xdp_egress_restricted {
                ControlStatus::Passed
            } else {
                ControlStatus::Warning
            },
            evidence: if xdp_egress_restricted {
                "XDP egress drop filter enforcing namespace boundaries and CIDR allowlists"
                    .to_string()
            } else {
                "Some namespaces lack explicit NetworkPolicy; traffic falls back to bridge default"
                    .to_string()
            },
            remediation: if !xdp_egress_restricted {
                Some(
                    "Deploy default-deny KwallSecurityPolicy to unrestricted namespaces"
                        .to_string(),
                )
            } else {
                None
            },
        });

        // CIS 4.1.5: Audit logging
        evals.push(ControlEvaluation {
            control_id: "CIS-4.1.5".to_string(),
            title: "Host Syscall Audit Ingestion".to_string(),
            description: "Ingest and chain raw kernel audit logs for tamper-evident reporting"
                .to_string(),
            status: if auditd_ingestion_healthy {
                ControlStatus::Passed
            } else {
                ControlStatus::Warning
            },
            evidence: if auditd_ingestion_healthy {
                "Ring-buffer audit queue operating with zero backlog drops".to_string()
            } else {
                "Audit queue warning observed during high load peak".to_string()
            },
            remediation: None,
        });

        Self::compile_report(
            ComplianceFramework::CisKubernetesV1_8,
            cluster_id,
            timestamp_ns,
            evals,
        )
    }

    /// Evaluates the cluster against SOC 2 Type II Security & Confidentiality Criteria.
    pub fn evaluate_soc2(
        cluster_id: &str,
        timestamp_ns: u64,
        tls_uprobe_inspection: bool,
        rootkit_self_protect: bool,
        hash_chained_audit: bool,
    ) -> ComplianceReport {
        let mut evals = Vec::new();

        // SOC2 CC6.1: Logical access and boundary protection
        evals.push(ControlEvaluation {
            control_id: "SOC2-CC6.1".to_string(),
            title: "Container & Multi-Cluster Logical Boundary Protection".to_string(),
            description: "Cryptographic identity and mTLS verification between service boundaries".to_string(),
            status: if tls_uprobe_inspection { ControlStatus::Passed } else { ControlStatus::Failed },
            evidence: if tls_uprobe_inspection {
                "Uprobe SSL_read/SSL_write plaintext inspection validates L7 tokens and micro-segmentation".to_string()
            } else {
                "TLS inspection uprobes inactive".to_string()
            },
            remediation: None,
        });

        // SOC2 CC6.8: Prevention and detection of malicious software & rootkits
        evals.push(ControlEvaluation {
            control_id: "SOC2-CC6.8".to_string(),
            title: "Malicious Software & Kernel Rootkit Defense".to_string(),
            description: "Continuous eBPF self-protection and kernel integrity verification".to_string(),
            status: if rootkit_self_protect { ControlStatus::Passed } else { ControlStatus::Failed },
            evidence: if rootkit_self_protect {
                "kwall-selfprotect scanner actively verifying kprobe hook tampering and memory safety".to_string()
            } else {
                "Self-protect engine offline".to_string()
            },
            remediation: None,
        });

        // SOC2 CC6.6: Tamper-evident audit logging
        evals.push(ControlEvaluation {
            control_id: "SOC2-CC6.6".to_string(),
            title: "Cryptographic Tamper-Evident Administrative Audit".to_string(),
            description: "SHA-256 hash chaining of all administrative and policy changes"
                .to_string(),
            status: if hash_chained_audit {
                ControlStatus::Passed
            } else {
                ControlStatus::Failed
            },
            evidence: if hash_chained_audit {
                "AuditLog ledger verified; hash chain intact with zero tampering events".to_string()
            } else {
                "Audit log integrity could not be verified".to_string()
            },
            remediation: None,
        });

        Self::compile_report(
            ComplianceFramework::Soc2Type2,
            cluster_id,
            timestamp_ns,
            evals,
        )
    }

    /// Evaluates the cluster against PCI-DSS v4.0 Network & System Security Requirements.
    pub fn evaluate_pci_dss(
        cluster_id: &str,
        timestamp_ns: u64,
        cde_isolated: bool,
        sqli_waf_active: bool,
        fim_active: bool,
    ) -> ComplianceReport {
        let mut evals = Vec::new();

        // PCI-DSS 1.2: Cardholder Data Environment (CDE) Network Segmentation
        evals.push(ControlEvaluation {
            control_id: "PCI-1.2".to_string(),
            title: "Network Security Controls & CDE Isolation".to_string(),
            description: "Restricting traffic between CDE namespaces and untrusted networks"
                .to_string(),
            status: if cde_isolated {
                ControlStatus::Passed
            } else {
                ControlStatus::Failed
            },
            evidence: if cde_isolated {
                "eBPF TC egress filters actively blocking non-CDE outbound communication"
                    .to_string()
            } else {
                "Payment namespace allows broad outbound egress".to_string()
            },
            remediation: if !cde_isolated {
                Some("Restrict CIDRs on payment-service to CDE gateway only".to_string())
            } else {
                None
            },
        });

        // PCI-DSS 6.4: Web Application Firewall (WAF)
        evals.push(ControlEvaluation {
            control_id: "PCI-6.4".to_string(),
            title: "Automated Technical Solution for Web Application Attacks".to_string(),
            description: "Real-time detection and blocking of SQLi, XSS, and SSRF attacks".to_string(),
            status: if sqli_waf_active { ControlStatus::Passed } else { ControlStatus::Failed },
            evidence: if sqli_waf_active {
                "kwall-application-security engine inspecting HTTP/TLS payload streams with OWASP signatures".to_string()
            } else {
                "WAF inspection disabled".to_string()
            },
            remediation: None,
        });

        // PCI-DSS 11.5: File Integrity Monitoring (FIM)
        evals.push(ControlEvaluation {
            control_id: "PCI-11.5".to_string(),
            title: "Change-Detection Mechanism (FIM) for Critical System Files".to_string(),
            description:
                "Alert on unauthorized modifications of critical system and application files"
                    .to_string(),
            status: if fim_active {
                ControlStatus::Passed
            } else {
                ControlStatus::Failed
            },
            evidence: if fim_active {
                "eBPF FIM module actively monitoring binaries, libraries, and config directories"
                    .to_string()
            } else {
                "FIM module not loaded".to_string()
            },
            remediation: None,
        });

        Self::compile_report(
            ComplianceFramework::PciDssV4_0,
            cluster_id,
            timestamp_ns,
            evals,
        )
    }

    fn compile_report(
        framework: ComplianceFramework,
        cluster_id: &str,
        timestamp_ns: u64,
        evaluations: Vec<ControlEvaluation>,
    ) -> ComplianceReport {
        let total_controls = evaluations.len();
        let passed_controls = evaluations
            .iter()
            .filter(|e| e.status == ControlStatus::Passed)
            .count();
        let warning_controls = evaluations
            .iter()
            .filter(|e| e.status == ControlStatus::Warning)
            .count();
        let failed_controls = evaluations
            .iter()
            .filter(|e| e.status == ControlStatus::Failed)
            .count();

        let score_percent = if total_controls > 0 {
            // Passed = 1.0, Warning = 0.5, Failed = 0.0
            let weighted_pass = (passed_controls as f64) + ((warning_controls as f64) * 0.5);
            (weighted_pass / (total_controls as f64)) * 100.0
        } else {
            100.0
        };

        ComplianceReport {
            framework,
            cluster_id: cluster_id.to_string(),
            timestamp_ns,
            score_percent,
            total_controls,
            passed_controls,
            warning_controls,
            failed_controls,
            evaluations,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cis_benchmark_evaluation() {
        let rep = ComplianceEngine::evaluate_cis(
            "prod-us-east-1",
            1_700_000_000_000_000_000,
            true, // lsm_active
            true, // fim_active
            true, // xdp_egress_restricted
            true, // auditd_ingestion_healthy
        );

        assert_eq!(rep.framework, ComplianceFramework::CisKubernetesV1_8);
        assert_eq!(rep.total_controls, 4);
        assert_eq!(rep.passed_controls, 4);
        assert_eq!(rep.failed_controls, 0);
        assert_eq!(rep.score_percent, 100.0);

        let scorecard = rep.generate_scorecard();
        assert!(scorecard.contains("CIS-5.2.1"));
        assert!(scorecard.contains("Overall Compliance Score: 100.0%"));
    }

    #[test]
    fn test_soc2_benchmark_evaluation() {
        let rep = ComplianceEngine::evaluate_soc2(
            "stage-cluster",
            1_700_000_000_000_000_000,
            true,
            true,
            true,
        );

        assert_eq!(rep.framework, ComplianceFramework::Soc2Type2);
        assert_eq!(rep.score_percent, 100.0);
        let json = rep.export_json();
        assert_eq!(json["framework"], "Soc2Type2");
    }

    #[test]
    fn test_pci_dss_partial_failure() {
        let rep = ComplianceEngine::evaluate_pci_dss(
            "finance-cluster",
            1_700_000_000_000_000_000,
            false, // CDE NOT isolated
            true,  // WAF active
            true,  // FIM active
        );

        assert_eq!(rep.framework, ComplianceFramework::PciDssV4_0);
        assert_eq!(rep.passed_controls, 2);
        assert_eq!(rep.failed_controls, 1);
        assert!((rep.score_percent - 66.66).abs() < 0.1);

        let fail_eval = rep
            .evaluations
            .iter()
            .find(|e| e.control_id == "PCI-1.2")
            .unwrap();
        assert_eq!(fail_eval.status, ControlStatus::Failed);
        assert!(fail_eval.remediation.is_some());
    }
}
