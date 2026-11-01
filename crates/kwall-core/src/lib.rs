//! # kwall-core
//!
//! Foundational domain types, traits, error models, and constants for KWALL.
//!
//! Follows strict zero-cost abstractions, explicit error models, and no unnecessary allocations.

pub mod constants;
pub mod error;
pub mod traits;
pub mod types;

pub use constants::*;
pub use error::{KwallError, Result};
pub use traits::{EventFilter, HealthCheckable, Lifecycle};
pub use types::*;
