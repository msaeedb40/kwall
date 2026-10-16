use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::types::{CidrRule, EndpointSelector, PolicyStatus, PortRule};

#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KWALLNetworkPolicy",
    plural = "kwallnetworkpolicies",
    namespaced,
    status = "PolicyStatus"
)]
pub struct KWALLNetworkPolicySpec {
    pub endpoint_selector: EndpointSelector,
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
    #[serde(default)]
    pub egress: Vec<EgressRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IngressRule {
    #[serde(default)]
    pub from_endpoints: Vec<EndpointSelector>,
    #[serde(default)]
    pub from_cidrs: Vec<CidrRule>,
    #[serde(default)]
    pub ports: Vec<PortRule>,
    #[serde(default = "default_action_allow")]
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EgressRule {
    #[serde(default)]
    pub to_endpoints: Vec<EndpointSelector>,
    #[serde(default)]
    pub to_cidrs: Vec<CidrRule>,
    #[serde(default)]
    pub ports: Vec<PortRule>,
    #[serde(default = "default_action_allow")]
    pub action: String,
}

fn default_action_allow() -> String {
    "Allow".to_string()
}
