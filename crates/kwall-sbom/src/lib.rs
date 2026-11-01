//! KWALL Supply Chain Security, Provenance Verification, and Runtime SBOM Drift Engine.
//!
//! Provides image signature validation (Cosign / Sigstore), CycloneDX and SPDX SBOM parsing,
//! real-time `execve` runtime binary drift detection, and Container File Integrity Monitoring (FIM).

pub mod drift;
pub mod fim;
pub mod parser;
pub mod provenance;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub use drift::RuntimeDriftDetector;
pub use fim::{FileIntegrityMonitor, FimEventType, DEFAULT_WATCHED_DIRS};
use kwall_detection::alert::ThreatAlert;
pub use parser::{
    SbomCatalog, SbomComponent, SbomDocument, SbomFormat, SbomParseError, SbomParser,
    WorkloadSbomProfile,
};
pub use provenance::{
    CosignSignaturePayload, ImageReference, ProvenanceError, ProvenancePolicy, ProvenanceValidator,
};

/// Aggregate runtime metrics for supply chain security.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SupplyChainMetrics {
    pub total_sboms_ingested: u64,
    pub total_images_verified: u64,
    pub drift_alerts_emitted: u64,
    pub fim_alerts_emitted: u64,
}

/// Unified Supply Chain Security Engine orchestrating provenance, cataloging, drift, and FIM.
pub struct SupplyChainEngine {
    pub validator: ProvenanceValidator,
    pub catalog: Arc<SbomCatalog>,
    pub drift_detector: RuntimeDriftDetector,
    pub fim_monitor: FileIntegrityMonitor,
    total_sboms: AtomicU64,
    total_verified: AtomicU64,
    drift_alerts: AtomicU64,
    fim_alerts: AtomicU64,
}

impl Default for SupplyChainEngine {
    fn default() -> Self {
        Self::new(ProvenancePolicy::default())
    }
}

impl SupplyChainEngine {
    /// Creates a new engine with the specified image provenance policy.
    #[must_use]
    pub fn new(policy: ProvenancePolicy) -> Self {
        let catalog = Arc::new(SbomCatalog::new());
        let drift_detector = RuntimeDriftDetector::new(Arc::clone(&catalog));
        let fim_monitor = FileIntegrityMonitor::new(Arc::clone(&catalog));

        Self {
            validator: ProvenanceValidator::new(policy),
            catalog,
            drift_detector,
            fim_monitor,
            total_sboms: AtomicU64::new(0),
            total_verified: AtomicU64::new(0),
            drift_alerts: AtomicU64::new(0),
            fim_alerts: AtomicU64::new(0),
        }
    }

    /// Validates an incoming container image before pod admission.
    #[allow(clippy::result_large_err)]
    pub fn verify_image_admission(
        &self,
        image_str: &str,
        signature: Option<&CosignSignaturePayload>,
    ) -> Result<(), ThreatAlert> {
        self.total_verified.fetch_add(1, Ordering::Relaxed);
        let img_ref = ImageReference::parse(image_str).map_err(|e| {
            let now = kwall_common::utilities::current_timestamp_ns();
            ThreatAlert::new(
                format!("prov-parse-err-{}", now),
                now,
                kwall_core::types::Severity::Error,
                kwall_detection::alert::ThreatCategory::ImageProvenanceViolation,
                Some("T1204.003"),
                "Invalid Container Image Reference Format",
                e.to_string(),
                None,
                serde_json::json!({ "raw_image": image_str }),
                "Review Kubernetes pod specification image field".to_string(),
            )
        })?;

        self.validator.validate(&img_ref, signature)
    }

    /// Ingests and registers an SBOM document for a workload.
    pub fn ingest_workload_sbom(
        &self,
        workload_id: &str,
        sbom_content: &str,
    ) -> Result<SbomDocument, SbomParseError> {
        let doc = SbomParser::parse(sbom_content)?;
        self.catalog.register_sbom(workload_id, &doc);
        self.total_sboms.fetch_add(1, Ordering::Relaxed);
        Ok(doc)
    }

    /// Evaluates a runtime process execution event for SBOM drift.
    pub fn on_process_exec(
        &self,
        workload_id: &str,
        binary_path: &str,
        comm: &str,
        pid: u32,
        uid: u32,
    ) -> Option<ThreatAlert> {
        let alert = self
            .drift_detector
            .inspect_execution(workload_id, binary_path, comm, pid, uid);
        if alert.is_some() {
            self.drift_alerts.fetch_add(1, Ordering::Relaxed);
        }
        alert
    }

    /// Evaluates a container filesystem mutation event for FIM violations.
    pub fn on_filesystem_change(
        &self,
        workload_id: &str,
        file_path: &str,
        event_type: FimEventType,
        current_sha256: Option<&str>,
        process_pid: u32,
        process_comm: &str,
    ) -> Option<ThreatAlert> {
        let alert = self.fim_monitor.evaluate_change(
            workload_id,
            file_path,
            event_type,
            current_sha256,
            process_pid,
            process_comm,
        );
        if alert.is_some() {
            self.fim_alerts.fetch_add(1, Ordering::Relaxed);
        }
        alert
    }

    /// Retrieves aggregate supply chain statistics.
    #[must_use]
    pub fn get_metrics(&self) -> SupplyChainMetrics {
        SupplyChainMetrics {
            total_sboms_ingested: self.total_sboms.load(Ordering::Relaxed),
            total_images_verified: self.total_verified.load(Ordering::Relaxed),
            drift_alerts_emitted: self.drift_alerts.load(Ordering::Relaxed),
            fim_alerts_emitted: self.fim_alerts.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_chain_engine_lifecycle() {
        let engine = SupplyChainEngine::default();

        // 1. Ingest SBOM
        let cyclonedx_json = r#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "name": "my-app",
                    "version": "1.0.0",
                    "properties": [
                        { "name": "kwall:file_path", "value": "/app/my-app" }
                    ]
                }
            ]
        }"#;

        assert!(engine
            .ingest_workload_sbom("container-frontend-1", cyclonedx_json)
            .is_ok());

        // 2. Normal execution allowed
        assert!(engine
            .on_process_exec("container-frontend-1", "/app/my-app", "my-app", 10, 0)
            .is_none());

        // 3. Staging directory execution flagged
        let drift_alert = engine.on_process_exec(
            "container-frontend-1",
            "/tmp/reverse_shell",
            "reverse_shell",
            99,
            0,
        );
        assert!(drift_alert.is_some());

        // 4. Dropped binary in /usr/bin flagged by FIM
        let fim_alert = engine.on_filesystem_change(
            "container-frontend-1",
            "/usr/bin/hijacked",
            FimEventType::Created,
            Some("12345"),
            99,
            "reverse_shell",
        );
        assert!(fim_alert.is_some());

        let metrics = engine.get_metrics();
        assert_eq!(metrics.total_sboms_ingested, 1);
        assert_eq!(metrics.drift_alerts_emitted, 1);
        assert_eq!(metrics.fim_alerts_emitted, 1);
    }
}
