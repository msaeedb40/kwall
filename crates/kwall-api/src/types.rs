use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EndpointSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub match_namespaces: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PortRule {
    pub port: u16,
    #[serde(default = "default_proto_tcp")]
    pub protocol: String,
}

fn default_proto_tcp() -> String {
    "TCP".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CidrRule {
    pub cidr: String,
    #[serde(default)]
    pub except: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct PolicyStatus {
    pub state: String,
    pub active_nodes: u32,
    pub last_applied_time: Option<String>,
    pub error_message: Option<String>,
}
