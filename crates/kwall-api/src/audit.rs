//! Tamper-Evident Cryptographic Administrative Audit Logging.
//!
//! Maintains an immutable, SHA-256 hash-chained ledger for all administrative actions,
//! policy deployments, and autonomous remediation actions in KWALL.

use crate::auth::{RbacRole, SecAction, SecResource};
use kwall_l7::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Genesis block hash for KWALL audit chains.
pub const AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Audit logging errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("Chain sequence violation: expected {expected}, found {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("Hash chain corruption at sequence {sequence}: expected prev_hash '{expected_prev}', found '{actual_prev}'")]
    HashChainBroken {
        sequence: u64,
        expected_prev: String,
        actual_prev: String,
    },
    #[error("Cryptographic digest mismatch at sequence {sequence}: computed '{computed}', stored '{stored}'")]
    DigestTampered {
        sequence: u64,
        computed: String,
        stored: String,
    },
    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Execution status of the audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStatus {
    Success,
    Denied,
    Failed,
}

impl std::fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS"),
            Self::Denied => write!(f, "DENIED"),
            Self::Failed => write!(f, "FAILED"),
        }
    }
}

/// An individual immutable record within the administrative audit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Monotonically increasing sequence number (0-indexed or 1-indexed)
    pub sequence: u64,
    /// Nanoseconds since UNIX epoch
    pub timestamp_ns: u64,
    /// Actor username, service account, or autonomous agent id
    pub actor: String,
    /// Enterprise RBAC role held during execution
    pub role: RbacRole,
    /// Security action performed
    pub action: SecAction,
    /// Target resource category
    pub resource: SecResource,
    /// Identifier or URI of the targeted resource
    pub resource_id: String,
    /// Outcome status of the operation
    pub status: AuditStatus,
    /// Arbitrary context parameters (diff, reason, IP, etc.)
    pub details: serde_json::Value,
    /// Cryptographic SHA-256 hash of the immediately preceding record
    pub prev_hash: String,
    /// Cryptographic SHA-256 hash of this record's payload and `prev_hash`
    pub record_hash: String,
}

impl AuditRecord {
    /// Computes the deterministic SHA-256 digest for an audit entry payload.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_digest(
        sequence: u64,
        timestamp_ns: u64,
        actor: &str,
        role: &RbacRole,
        action: SecAction,
        resource: SecResource,
        resource_id: &str,
        status: AuditStatus,
        details: &serde_json::Value,
        prev_hash: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{:?}:{:?}:{:?}:{}:{}:{}:{}",
            sequence,
            timestamp_ns,
            actor,
            role,
            action,
            resource,
            resource_id,
            status,
            details,
            prev_hash
        );
        sha256_hex(payload.as_bytes())
    }
}

/// Cryptographically chained administrative audit log.
#[derive(Debug, Clone)]
pub struct AuditLog {
    records: Arc<RwLock<Vec<AuditRecord>>>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    /// Creates a new empty audit log with genesis initialized.
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Appends a new immutable administrative action record to the chained log.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        timestamp_ns: u64,
        actor: impl Into<String>,
        role: RbacRole,
        action: SecAction,
        resource: SecResource,
        resource_id: impl Into<String>,
        status: AuditStatus,
        details: serde_json::Value,
    ) -> Result<AuditRecord, AuditError> {
        let mut records = self
            .records
            .write()
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let sequence = records.len() as u64;
        let prev_hash = if let Some(last) = records.last() {
            last.record_hash.clone()
        } else {
            AUDIT_GENESIS_HASH.to_string()
        };

        let actor_str = actor.into();
        let resource_id_str = resource_id.into();

        let record_hash = AuditRecord::compute_digest(
            sequence,
            timestamp_ns,
            &actor_str,
            &role,
            action,
            resource,
            &resource_id_str,
            status,
            &details,
            &prev_hash,
        );

        let record = AuditRecord {
            sequence,
            timestamp_ns,
            actor: actor_str,
            role,
            action,
            resource,
            resource_id: resource_id_str,
            status,
            details,
            prev_hash,
            record_hash,
        };

        records.push(record.clone());
        Ok(record)
    }

    /// Verifies the cryptographic integrity of the entire audit chain.
    ///
    /// Validates:
    /// 1. Sequence numbers are strictly monotonic: 0, 1, 2, ...
    /// 2. `prev_hash` of each block matches the `record_hash` of the prior block.
    /// 3. `record_hash` matches recomputed SHA-256 digest of record payload.
    pub fn verify_integrity(&self) -> Result<bool, AuditError> {
        let records = self
            .records
            .read()
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let mut expected_prev = AUDIT_GENESIS_HASH.to_string();

        for (idx, record) in records.iter().enumerate() {
            let seq = idx as u64;
            if record.sequence != seq {
                return Err(AuditError::SequenceMismatch {
                    expected: seq,
                    actual: record.sequence,
                });
            }

            if record.prev_hash != expected_prev {
                return Err(AuditError::HashChainBroken {
                    sequence: seq,
                    expected_prev,
                    actual_prev: record.prev_hash.clone(),
                });
            }

            let computed = AuditRecord::compute_digest(
                record.sequence,
                record.timestamp_ns,
                &record.actor,
                &record.role,
                record.action,
                record.resource,
                &record.resource_id,
                record.status,
                &record.details,
                &record.prev_hash,
            );

            if computed != record.record_hash {
                return Err(AuditError::DigestTampered {
                    sequence: seq,
                    computed,
                    stored: record.record_hash.clone(),
                });
            }

            expected_prev = record.record_hash.clone();
        }

        Ok(true)
    }

    /// Returns a snapshot of all records in the log.
    pub fn get_records(&self) -> Vec<AuditRecord> {
        self.records.read().map(|r| r.clone()).unwrap_or_default()
    }

    /// Exports all records as a JSON string.
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let records = self.get_records();
        serde_json::to_string_pretty(&records)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_append_and_verify() {
        let audit = AuditLog::new();

        // 1. Initial empty chain is valid
        assert!(audit.verify_integrity().unwrap());

        // 2. Append record 0
        let r0 = audit
            .append(
                1_000_000,
                "admin@enterprise.internal",
                RbacRole::Admin,
                SecAction::Write,
                SecResource::Policy,
                "policy-allow-ingress",
                AuditStatus::Success,
                serde_json::json!({ "version": "1.0" }),
            )
            .unwrap();

        assert_eq!(r0.sequence, 0);
        assert_eq!(r0.prev_hash, AUDIT_GENESIS_HASH);
        assert!(!r0.record_hash.is_empty());

        // 3. Append record 1
        let r1 = audit
            .append(
                1_000_100,
                "analyst@enterprise.internal",
                RbacRole::SecurityAnalyst,
                SecAction::Execute,
                SecResource::Workload,
                "payment-pod-4kx",
                AuditStatus::Success,
                serde_json::json!({ "action": "quarantine" }),
            )
            .unwrap();

        assert_eq!(r1.sequence, 1);
        assert_eq!(r1.prev_hash, r0.record_hash);

        // 4. Verify chain integrity
        assert!(audit.verify_integrity().unwrap());
        assert_eq!(audit.get_records().len(), 2);
    }

    #[test]
    fn test_audit_tamper_detection() {
        let audit = AuditLog::new();

        audit
            .append(
                100,
                "user1",
                RbacRole::Admin,
                SecAction::Read,
                SecResource::Cluster,
                "c1",
                AuditStatus::Success,
                serde_json::json!({}),
            )
            .unwrap();

        audit
            .append(
                200,
                "user2",
                RbacRole::PolicyEditor,
                SecAction::Write,
                SecResource::Policy,
                "p1",
                AuditStatus::Success,
                serde_json::json!({}),
            )
            .unwrap();

        // Tamper with record 0's actor
        {
            let mut records = audit.records.write().unwrap();
            records[0].actor = "hacker@evil.com".to_string();
        }

        // Integrity check MUST fail with DigestTampered
        let err = audit.verify_integrity().unwrap_err();
        assert!(matches!(
            err,
            AuditError::DigestTampered { sequence: 0, .. }
        ));
    }

    #[test]
    fn test_audit_export_json() {
        let audit = AuditLog::new();
        audit
            .append(
                500,
                "auditor",
                RbacRole::Auditor,
                SecAction::Approve,
                SecResource::AuditLog,
                "ledger",
                AuditStatus::Success,
                serde_json::json!({ "approved": true }),
            )
            .unwrap();

        let json = audit.export_json().unwrap();
        assert!(json.contains("auditor"));
        assert!(json.contains("AuditLog"));
        assert!(json.contains("Approve"));
    }
}
