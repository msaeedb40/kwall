//! System-wide constants for KWALL.

/// Current platform specification version.
pub const KWALL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default maximum ring buffer capacity in bytes (must be power of two).
pub const DEFAULT_RING_BUFFER_SIZE_BYTES: usize = 16 * 1024 * 1024; // 16 MB

/// Default capacity for flow-tracking LRU maps.
pub const DEFAULT_FLOW_MAP_CAPACITY: u32 = 131072; // 128k entries

/// Default capacity for process-tracking maps.
pub const DEFAULT_PROCESS_MAP_CAPACITY: u32 = 65536; // 64k entries

/// Standard internal event protocol version.
pub const EVENT_PROTOCOL_VERSION: u16 = 1;
