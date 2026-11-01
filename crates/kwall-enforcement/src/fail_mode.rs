//! Enforcement fail-mode configuration.

use serde::{Deserialize, Serialize};

/// Fallback security posture during control-plane disconnect or failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Allow traffic through if rules cannot be verified (availability first).
    FailOpen,
    /// Block traffic if rules cannot be verified (security first).
    #[default]
    FailClosed,
}
