//! Common lifecycle and subsystem traits.

use crate::error::Result;

/// Subsystem lifecycle contract.
pub trait Lifecycle: Send + Sync {
    /// Initialize internal buffers and prepare dependencies.
    fn initialize(&mut self) -> Result<()>;

    /// Start processing background workers.
    fn start(&mut self) -> Result<()>;

    /// Gracefully stop execution, flushing buffers and releasing kernel hooks.
    fn stop(&mut self) -> Result<()>;
}

/// Health and readiness reporting contract.
pub trait HealthCheckable: Send + Sync {
    /// Check whether the component is operational and ready to serve traffic.
    fn is_healthy(&self) -> bool;

    /// Descriptive status message or diagnostics.
    fn status_message(&self) -> &str;
}

/// Dynamic event filtering trait.
pub trait EventFilter<E>: Send + Sync {
    /// Returns true if the event should be processed, false if dropped.
    fn matches(&self, event: &E) -> bool;
}
