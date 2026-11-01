//! Runtime binary drift detection and executable deviation analysis.
//!
//! Correlates runtime eBPF `sched_process_exec` / `execve` events against container SBOM catalogs,
//! identifying unapproved binaries, staging directory execution, and process masquerading.

use std::sync::Arc;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};

use crate::parser::SbomCatalog;

/// Staging directories commonly abused by attackers for payload drop and staging.
const TRANSIENT_STAGING_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run", "/var/run"];

/// Runtime detector correlating active container processes against the SBOM baseline.
pub struct RuntimeDriftDetector {
    pub catalog: Arc<SbomCatalog>,
}

impl RuntimeDriftDetector {
    /// Creates a new detector wrapping an SbomCatalog.
    pub fn new(catalog: Arc<SbomCatalog>) -> Self {
        Self { catalog }
    }

    /// Evaluates a process execution event for SBOM drift and unauthorized execution.
    pub fn inspect_execution(
        &self,
        workload_id: &str,
        binary_path: &str,
        comm: &str,
        pid: u32,
        uid: u32,
    ) -> Option<ThreatAlert> {
        let now = kwall_common::utilities::current_timestamp_ns();

        // 1. Detection: Execution from transient / writable directories (/tmp, /dev/shm, etc.)
        for &staging_dir in TRANSIENT_STAGING_DIRS {
            if binary_path.starts_with(staging_dir) {
                return Some(ThreatAlert::new(
                    format!("drift-transient-exec-{}", now),
                    now,
                    Severity::Critical,
                    ThreatCategory::SbomDrift,
                    Some("T1059.004"),
                    "Executable Executed from Transient Staging Directory",
                    format!(
                        "Process '{comm}' (PID {pid}, UID {uid}) was executed from temporary staging path: {binary_path}"
                    ),
                    None,
                    serde_json::json!({
                        "workload_id": workload_id,
                        "binary_path": binary_path,
                        "comm": comm,
                        "pid": pid,
                        "uid": uid,
                        "staging_directory": staging_dir
                    }),
                    "Immediately terminate process, freeze container, and enforce read-only root filesystem"
                        .to_string(),
                ));
            }
        }

        // 2. Detection: Uncataloged binary execution not declared in container SBOM
        if !self.catalog.is_binary_approved(workload_id, binary_path) {
            return Some(ThreatAlert::new(
                format!("drift-uncataloged-binary-{}", now),
                now,
                Severity::Error,
                ThreatCategory::SbomDrift,
                Some("T1204.002"),
                "Runtime Binary Drift: Uncataloged Executable Executed",
                format!(
                    "Executable '{binary_path}' (comm '{comm}', PID {pid}) is not declared in workload '{workload_id}' SBOM baseline"
                ),
                None,
                serde_json::json!({
                    "workload_id": workload_id,
                    "binary_path": binary_path,
                    "comm": comm,
                    "pid": pid,
                    "uid": uid
                }),
                "Quarantine pod and verify whether image was modified post-build or breached via RCE"
                    .to_string(),
            ));
        }

        // 3. Detection: Process Masquerading (comm name mismatch)
        if let Some(base_name) = binary_path.rsplit('/').next() {
            if !base_name.is_empty() && comm != base_name && !comm.starts_with(base_name) {
                // Ignore standard wrappers like env or sh launching scripts
                if base_name != "env"
                    && base_name != "sh"
                    && base_name != "bash"
                    && base_name != "python3"
                {
                    return Some(ThreatAlert::new(
                        format!("drift-masquerade-{}", now),
                        now,
                        Severity::Warning,
                        ThreatCategory::SbomDrift,
                        Some("T1036.005"),
                        "Process Name Masquerading Detected",
                        format!(
                            "Process name '{comm}' deviates from disk binary basename '{base_name}' ({binary_path})"
                        ),
                        None,
                        serde_json::json!({
                            "workload_id": workload_id,
                            "binary_path": binary_path,
                            "comm": comm,
                            "basename": base_name,
                            "pid": pid
                        }),
                        "Inspect process cmdline and memory for prctl(PR_SET_NAME) evasion"
                            .to_string(),
                    ));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::SbomDocument;
    use crate::parser::SbomFormat;

    #[test]
    fn test_drift_detection_transient_execution() {
        let catalog = Arc::new(SbomCatalog::new());
        let detector = RuntimeDriftDetector::new(catalog);

        let alert =
            detector.inspect_execution("pod-web-1", "/tmp/krypton_miner", "krypton_miner", 4521, 0);

        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::SbomDrift);
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1059.004"));
    }

    #[test]
    fn test_drift_detection_uncataloged_binary() {
        let catalog = Arc::new(SbomCatalog::new());
        // Register an empty SBOM with only default primitives
        let doc = SbomDocument {
            format: SbomFormat::CycloneDx,
            spec_version: "1.5".to_string(),
            serial_number: None,
            components: Vec::new(),
        };
        catalog.register_sbom("pod-web-1", &doc);

        let detector = RuntimeDriftDetector::new(catalog);

        // Allowed primitive
        assert!(detector
            .inspect_execution("pod-web-1", "/bin/sh", "sh", 100, 0)
            .is_none());

        // Uncataloged binary
        let alert = detector.inspect_execution("pod-web-1", "/usr/local/bin/nc", "nc", 101, 1000);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::SbomDrift);
        assert_eq!(a.severity, Severity::Error);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1204.002"));
    }
}
