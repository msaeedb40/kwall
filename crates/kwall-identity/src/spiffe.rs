//! SPIFFE workload identity parsing and generation.

use kwall_core::error::{KwallError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Strongly typed SPIFFE Workload Identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpiffeId {
    pub trust_domain: String,
    pub namespace: String,
    pub service_account: String,
}

impl SpiffeId {
    /// Constructs a new SPIFFE ID from trust domain, namespace, and service account.
    pub fn new(
        trust_domain: impl Into<String>,
        namespace: impl Into<String>,
        sa: impl Into<String>,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            namespace: namespace.into(),
            service_account: sa.into(),
        }
    }

    /// Parses a standard SPIFFE URI: `spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>`.
    pub fn parse(uri: &str) -> Result<Self> {
        let stripped = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| KwallError::Internal(format!("Invalid SPIFFE scheme: {uri}")))?;

        let parts: Vec<&str> = stripped.split('/').collect();
        if parts.len() == 5 && parts[1] == "ns" && parts[3] == "sa" {
            Ok(Self {
                trust_domain: parts[0].to_string(),
                namespace: parts[2].to_string(),
                service_account: parts[4].to_string(),
            })
        } else {
            Err(KwallError::Internal(format!(
                "Invalid SPIFFE URI format: {uri}"
            )))
        }
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spiffe://{}/ns/{}/sa/{}",
            self.trust_domain, self.namespace, self.service_account
        )
    }
}
