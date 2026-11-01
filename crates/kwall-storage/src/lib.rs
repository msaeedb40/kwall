//! KWALL Pluggable Storage Connectors.
//!
//! Provides relational storage adapters (PostgreSQL) for transactional audit records,
//! analytical columnar storage sinks (ClickHouse) for petabyte-scale network flow logs,
//! a dual-engine hybrid storage router, and cold-storage archival with Parquet/ZSTD.

pub mod archival;
pub mod clickhouse;
pub mod hybrid;
pub mod memory;
pub mod postgres;
pub mod traits;

pub use archival::{
    ArchivalError, ArchivalJob, ArchivalJobStatus, ArchivalManager, ArchivalStats, DataPartition,
    ObjectStorageTarget,
};
pub use clickhouse::{ClickHouseConfig, ClickHouseStorage};
pub use hybrid::{FlowRecord, HybridStorageRouter, RiskScoreRecord, RouterStats};
pub use memory::MemoryStorage;
pub use postgres::{PostgresConfig, PostgresStorage};
pub use traits::{StorageBackend, StorageError};
