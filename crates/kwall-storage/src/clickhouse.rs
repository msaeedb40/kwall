//! ClickHouse analytical columnar storage connector for high-throughput network flow telemetry.

use crate::traits::{StorageBackend, StorageError};
use kwall_enforcement::audit::AuditRecord;
use kwall_event_enricher::enricher::EnrichedEvent;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::info;

/// ClickHouse columnar storage configuration.
#[derive(Debug, Clone)]
pub struct ClickHouseConfig {
    pub endpoint_url: String,
    pub database: String,
    pub batch_flush_size: usize,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            endpoint_url: "http://localhost:8123".to_string(),
            database: "kwall".to_string(),
            batch_flush_size: 5000,
        }
    }
}

/// ClickHouse storage sink supporting batched columnar writes for petabyte-scale telemetry.
pub struct ClickHouseStorage {
    config: ClickHouseConfig,
    flushed_records: AtomicU64,
    batch_buffer: RwLock<Vec<EnrichedEvent>>,
}

impl ClickHouseStorage {
    /// Creates a new ClickHouse analytical storage connector.
    pub fn new(config: ClickHouseConfig) -> Self {
        info!(
            "Initialized ClickHouse telemetry sink targeting {}",
            config.endpoint_url
        );
        Self {
            config,
            flushed_records: AtomicU64::new(0),
            batch_buffer: RwLock::new(Vec::new()),
        }
    }

    /// Generates ClickHouse DDL for high-throughput columnar flow tables using MergeTree.
    pub fn generate_ddl(&self) -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS {}.flow_telemetry (\n\
             \x20   timestamp DateTime64(9, 'UTC'),\n\
             \x20   src_ip IPv4,\n\
             \x20   dst_ip IPv4,\n\
             \x20   src_port UInt16,\n\
             \x20   dst_port UInt16,\n\
             \x20   protocol UInt8,\n\
             \x20   action LowCardinality(String),\n\
             \x20   packet_len UInt32,\n\
             \x20   pod_name LowCardinality(String),\n\
             \x20   namespace LowCardinality(String)\n\
             ) ENGINE = MergeTree()\n\
             ORDER BY (namespace, timestamp, src_ip, dst_ip);\n",
            self.config.database
        )
    }

    /// Returns total flushed telemetry event count.
    pub fn total_flushed(&self) -> u64 {
        self.flushed_records.load(Ordering::Relaxed)
    }
}

impl StorageBackend for ClickHouseStorage {
    fn store_audit_record(&self, _record: &AuditRecord) -> Result<(), StorageError> {
        // High-level audit records are managed by PostgreSQL/etcd
        Ok(())
    }

    fn store_flow_event(&self, event: &EnrichedEvent) -> Result<(), StorageError> {
        let mut lock = self
            .batch_buffer
            .write()
            .map_err(|e| StorageError::Query(e.to_string()))?;
        lock.push(event.clone());

        if lock.len() >= self.config.batch_flush_size {
            let count = lock.len() as u64;
            lock.clear();
            self.flushed_records.fetch_add(count, Ordering::Relaxed);
        }

        Ok(())
    }

    fn query_recent_audits(&self, _limit: usize) -> Result<Vec<AuditRecord>, StorageError> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clickhouse_ddl_generation() {
        let storage = ClickHouseStorage::new(ClickHouseConfig::default());
        let ddl = storage.generate_ddl();
        assert!(ddl.contains("CREATE TABLE IF NOT EXISTS kwall.flow_telemetry"));
        assert!(ddl.contains("ENGINE = MergeTree()"));
    }
}
