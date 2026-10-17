use crate::types::PolicyStatus;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KWALLDDoSPolicy",
    plural = "kwallddospolicies",
    namespaced,
    status = "PolicyStatus"
)]
pub struct KWALLDDoSPolicySpec {
    pub max_syn_per_second: u32,
    pub max_udp_packets_per_second: u32,
    pub max_connections_per_ip: u32,
    #[serde(default)]
    pub enable_xdp_early_drop: bool,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
}
