//! Controller for validating and supervising KWALL security CRD lifecycles.

use kube::{Client, ResourceExt};
use kwall_policy::crd::{KwallNetworkPolicy, KwallRuntimePolicy};
use kwall_policy::validator::{validate_network_policy, validate_runtime_policy};
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info};

/// Policy reconciliation errors.
#[derive(Debug, Error)]
pub enum PolicyReconcileError {
    #[error("Semantic validation failure: {0}")]
    Validation(String),
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

/// Context state for policy reconciliation loops.
pub struct PolicyContext {
    pub client: Client,
}

/// Reconciles a KwallNetworkPolicy declaration.
pub async fn reconcile_network_policy(
    policy: Arc<KwallNetworkPolicy>,
    _ctx: Arc<PolicyContext>,
) -> Result<(), PolicyReconcileError> {
    let name = policy.name_any();
    let namespace = policy.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling KwallNetworkPolicy: {namespace}/{name}");

    if let Err(err) = validate_network_policy(&policy.spec) {
        error!("KwallNetworkPolicy {namespace}/{name} failed validation: {err}");
        return Err(PolicyReconcileError::Validation(err.to_string()));
    }

    info!("KwallNetworkPolicy {namespace}/{name} validated successfully");
    Ok(())
}

/// Reconciles a KwallRuntimePolicy declaration.
pub async fn reconcile_runtime_policy(
    policy: Arc<KwallRuntimePolicy>,
    _ctx: Arc<PolicyContext>,
) -> Result<(), PolicyReconcileError> {
    let name = policy.name_any();
    let namespace = policy.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling KwallRuntimePolicy: {namespace}/{name}");

    if let Err(err) = validate_runtime_policy(&policy.spec) {
        error!("KwallRuntimePolicy {namespace}/{name} failed validation: {err}");
        return Err(PolicyReconcileError::Validation(err.to_string()));
    }

    info!("KwallRuntimePolicy {namespace}/{name} validated successfully");
    Ok(())
}
