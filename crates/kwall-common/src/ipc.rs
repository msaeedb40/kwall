use kwall_ebpf_common::{EndpointIdentity, MetricsCounter, PolicyKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub node_name: String,
    pub kernel_version: String,
    pub ebpf_ready: bool,
    pub active_interfaces: Vec<String>,
    pub endpoints_count: usize,
    pub policies_count: usize,
    pub drops_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentRequest {
    GetStatus,
    ListEndpoints,
    ListPolicies,
    GetMetrics,
    AddBlacklist {
        ip: u32,
    },
    RemoveBlacklist {
        ip: u32,
    },
    RegisterEndpoint {
        ip: u32,
        identity_id: u32,
        namespace_id: u32,
        pod_uid_hash: u64,
        ifindex: u32,
    },
    UnregisterEndpoint {
        ip: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentResponse {
    Status(NodeStatus),
    Endpoints(Vec<EndpointIdentity>),
    Policies(Vec<PolicyKey>),
    Metrics(MetricsCounter),
    Success,
    Error(String),
}
