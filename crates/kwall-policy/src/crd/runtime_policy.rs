//! KwallRuntimePolicy Custom Resource Definition.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Declarative Kubernetes Runtime Security Policy for KWALL.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KwallRuntimePolicy",
    namespaced
)]
pub struct KwallRuntimePolicySpec {
    pub pod_selector: HashMap<String, String>,
    pub allowed_executables: Option<Vec<String>>,
    pub blocked_executables: Option<Vec<String>>,
    pub protected_paths: Option<Vec<String>>,
    pub action: RuntimePolicyAction,
}

/// Enforcement action for runtime security rules.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuntimePolicyAction {
    Deny,
    Audit,
    Quarantine,
}
