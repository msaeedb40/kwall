use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::types::{EndpointSelector, PolicyStatus};

#[derive(CustomResource, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "kwall.io",
    version = "v1alpha1",
    kind = "KWALLFlowPolicy",
    plural = "kwallflowpolicies",
    namespaced,
    status = "PolicyStatus"
)]
pub struct KWALLFlowPolicySpec {
    pub endpoint_selector: EndpointSelector,
    #[serde(default = "default_sample_rate")]
    pub sample_rate: u32,
    #[serde(default)]
    pub export_dropped_only: bool,
    #[serde(default = "default_true")]
    pub export_l4_metrics: bool,
    #[serde(default)]
    pub destination_targets: Vec<String>,
}

fn default_sample_rate() -> u32 {
    1
}

fn default_true() -> bool {
    true
}
