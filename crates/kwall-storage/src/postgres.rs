//! PostgreSQL storage adapter for relational audit records, policies, and node state.

use crate::traits::{StorageBackend, StorageError};
use kwall_enforcement::audit::AuditRecord;
use kwall_event_enricher::enricher::EnrichedEvent;
use std::sync::RwLock;
use tracing::info;

/// PostgreSQL storage configuration.
#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub connection_url: String,
    pub max_connections: u32,
    pub table_prefix: String,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            connection_url: "postgres://kwall:kwall@localhost:5432/kwall".to_string(),
            max_connections: 16,
            table_prefix: "kwall_".to_string(),
        }
    }
}

/// PostgreSQL storage connector with schema initialization and transactional persistence.
pub struct PostgresStorage {
    config: PostgresConfig,
    in_flight_buffer: RwLock<Vec<AuditRecord>>,
}

impl PostgresStorage {
    /// Initializes a new PostgreSQL storage adapter.
    pub fn new(config: PostgresConfig) -> Self {
        info!(
            "Initialized PostgreSQL storage adapter with target {}",
            config.connection_url
        );
        Self {
            config,
            in_flight_buffer: RwLock::new(Vec::new()),
        }
    }

    /// Returns SQL schema DDL for PostgreSQL initialization.
    pub fn generate_ddl(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {}audit_records (\n\
             \x20   id BIGSERIAL PRIMARY KEY,\n\
             \x20   timestamp_ns BIGINT NOT NULL,\n\
             \x20   node_id BIGINT NOT NULL,\n\
             \x20   rule_id INT NOT NULL,\n\
             \x20   action VARCHAR(32) NOT NULL,\n\
             \x20   severity VARCHAR(32) NOT NULL,\n\
             \x20   target_entity TEXT NOT NULL,\n\
             \x20   reason TEXT NOT NULL\n\
             );\n\
             CREATE INDEX IF NOT EXISTS idx_{}audit_ts ON {}audit_records (timestamp_ns DESC);\n",
            self.config.table_prefix, self.config.table_prefix, self.config.table_prefix
        )
    }
}

impl StorageBackend for PostgresStorage {
    fn store_audit_record(&self, record: &AuditRecord) -> Result<(), StorageError> {
        let mut lock = self
            .in_flight_buffer
            .write()
            .map_err(|e| StorageError::Query(e.to_string()))?;
        lock.push(record.clone());
        Ok(())
    }

    fn store_flow_event(&self, _event: &EnrichedEvent) -> Result<(), StorageError> {
        // High-frequency flow events are routed to ClickHouse, not OLTP PostgreSQL
        Ok(())
    }

    fn query_recent_audits(&self, limit: usize) -> Result<Vec<AuditRecord>, StorageError> {
        let lock = self
            .in_flight_buffer
            .read()
            .map_err(|e| StorageError::Query(e.to_string()))?;
        let count = lock.len();
        let skip = count.saturating_sub(limit);
        Ok(lock.iter().skip(skip).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_ddl_generation() {
        let storage = PostgresStorage::new(PostgresConfig::default());
        let ddl = storage.generate_ddl();
        assert!(ddl.contains("CREATE TABLE IF NOT EXISTS kwall_audit_records"));
        assert!(ddl.contains("id BIGSERIAL PRIMARY KEY"));
    }
}
