//! Storage backend traits and error definitions.

use kwall_enforcement::audit::AuditRecord;
use kwall_event_enricher::enricher::EnrichedEvent;
use thiserror::Error;

/// Storage operation errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Connection failure: {0}")]
    Connection(String),
    #[error("Database query failed: {0}")]
    Query(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Abstract storage provider interface for telemetry, audit trails, and security policies.
pub trait StorageBackend: Send + Sync {
    /// Persists a non-repudiable policy enforcement audit record.
    fn store_audit_record(&self, record: &AuditRecord) -> Result<(), StorageError>;

    /// Persists high-throughput network flow telemetry.
    fn store_flow_event(&self, event: &EnrichedEvent) -> Result<(), StorageError>;

    /// Retrieves recent audit records up to limit.
    fn query_recent_audits(&self, limit: usize) -> Result<Vec<AuditRecord>, StorageError>;
}
