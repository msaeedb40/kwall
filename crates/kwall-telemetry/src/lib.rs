//! KWALL Telemetry, Metrics & Observability Subsystem.
//!
//! Provides Prometheus metrics collection and HTTP exposition, atomic pipeline
//! counters, OpenTelemetry-compatible distributed tracing span management, and
//! telemetry export.

pub mod metrics;
pub mod server;
pub mod tracing;

pub use metrics::TelemetryRegistry;
pub use server::start_metrics_server;
pub use tracing::TraceContext;
