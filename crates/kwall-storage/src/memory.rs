//! In-memory thread-safe storage implementation for development and testing.

use crate::traits::{StorageBackend, StorageError};
use kwall_enforcement::audit::AuditRecord;
use kwall_event_enricher::enricher::EnrichedEvent;
use std::sync::RwLock;

/// Thread-safe in-memory storage buffer.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    audits: RwLock<Vec<AuditRecord>>,
    flows: RwLock<Vec<EnrichedEvent>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StorageBackend for MemoryStorage {
    fn store_audit_record(&self, record: &AuditRecord) -> Result<(), StorageError> {
        let mut lock = self
            .audits
            .write()
            .map_err(|e| StorageError::Query(e.to_string()))?;
        lock.push(record.clone());
        Ok(())
    }

    fn store_flow_event(&self, event: &EnrichedEvent) -> Result<(), StorageError> {
        let mut lock = self
            .flows
            .write()
            .map_err(|e| StorageError::Query(e.to_string()))?;
        lock.push(event.clone());
        Ok(())
    }

    fn query_recent_audits(&self, limit: usize) -> Result<Vec<AuditRecord>, StorageError> {
        let lock = self
            .audits
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
    use kwall_core::types::PolicyAction;

    #[test]
    fn test_memory_storage_crud() {
        let storage = MemoryStorage::new();
        let record = AuditRecord::new(
            1234567,
            kwall_core::types::NodeId(1),
            42,
            PolicyAction::Block,
            "pod/default/frontend",
            "Denied by LPM trie rule",
        );

        storage
            .store_audit_record(&record)
            .expect("Store should succeed");
        let results = storage
            .query_recent_audits(10)
            .expect("Query should succeed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, 42);
        assert_eq!(results[0].target_entity, "pod/default/frontend");
    }
}
