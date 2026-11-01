//! # kwall-common
//!
//! Logging, telemetry counters, rate limiters, and system utilities for KWALL.

pub mod logging;
pub mod telemetry;
pub mod utilities;

pub use logging::{init_logging, LogFormat};
pub use telemetry::PipelineMetrics;
pub use utilities::{format_ipv4, RateLimiter};
