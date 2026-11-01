//! KwallNetworkPolicy Custom Resource Definition.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Declarative Kubernetes Network Policy for KWALL.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KwallNetworkPolicy",
    namespaced
)]
pub struct KwallNetworkPolicySpec {
    pub pod_selector: HashMap<String, String>,
    pub ingress: Option<Vec<NetworkRule>>,
    pub egress: Option<Vec<NetworkRule>>,
}

/// Network rule matching traffic by CIDR prefix, port, and protocol.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
pub struct NetworkRule {
    pub cidr: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub action: NetworkPolicyAction,
}

/// Enforcement action for network rules.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicyAction {
    Allow,
    Deny,
    Audit,
}
