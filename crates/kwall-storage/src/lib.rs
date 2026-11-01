//! KWALL Pluggable Storage Connectors.
//!
//! Provides relational storage adapters (PostgreSQL) for transactional audit records
//! and analytical columnar storage sinks (ClickHouse) for petabyte-scale network flow logs.

pub mod clickhouse;
pub mod memory;
pub mod postgres;
pub mod traits;

pub use clickhouse::{ClickHouseConfig, ClickHouseStorage};
pub use memory::MemoryStorage;
pub use postgres::{PostgresConfig, PostgresStorage};
pub use traits::{StorageBackend, StorageError};
